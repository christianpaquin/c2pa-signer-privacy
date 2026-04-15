"""
Web UI for C2PA Signer Privacy prototypes.

Wraps the BBS-signatures and ZK-proofs CLI binaries in a Flask web interface
for issuing credentials, signing, anonymizing, and verifying images.
"""

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

app = Flask(__name__)
app.secret_key = os.urandom(32)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
BBS_BIN = ROOT / "bbs-signatures" / "target" / "release"
ZK_BIN = ROOT / "zk-proofs" / "target" / "release"
BBS_FIXTURES = ROOT / "bbs-signatures" / "fixtures"
ZK_FIXTURES = ROOT / "zk-proofs" / "fixtures"
ZK_CERTS = ZK_FIXTURES / "certs"
ZK_CIRCUITS = ROOT / "zk-proofs" / "circuits"

UPLOAD_DIR = Path(tempfile.mkdtemp(prefix="c2pa_web_"))
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

# Background jobs for long-running operations (ZK proof generation)
jobs: dict[str, dict] = {}

# In-memory wallet for BBS credentials (simulates holder wallet)
wallet: list[dict] = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def unique_path(directory: Path, suffix: str) -> Path:
    return directory / f"{uuid.uuid4().hex}{suffix}"


def resolve_input_image(fixtures_dir: Path) -> Path | None:
    """Resolve uploaded image or sample image. Returns path or None."""
    image = request.files.get("image")
    sample = request.form.get("use_sample", "").strip()

    if image and image.filename and allowed_file(image.filename):
        suffix = Path(image.filename).suffix
        path = unique_path(UPLOAD_DIR, suffix)
        image.save(str(path))
        return path

    if sample:
        safe = Path(sample).name
        src = fixtures_dir / safe
        if src.exists():
            dest = unique_path(UPLOAD_DIR, src.suffix)
            shutil.copy2(src, dest)
            return dest

    return None


def run_cli(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run a CLI binary and capture output."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=600,
        cwd=cwd,
    )


def run_cli_background(job_id: str, args: list[str], output_filename: str,
                       cwd: str | None = None) -> None:
    """Run a CLI binary in a background thread, updating job status."""
    jobs[job_id]["status"] = "running"
    jobs[job_id]["started"] = time.time()
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=3600, cwd=cwd,
        )
        jobs[job_id]["elapsed"] = int(time.time() - jobs[job_id]["started"])
        if result.returncode == 0:
            jobs[job_id]["status"] = "done"
            jobs[job_id]["output"] = (result.stdout + result.stderr).strip()
            jobs[job_id]["output_filename"] = output_filename
        else:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["output"] = result.stderr.strip()
    except subprocess.TimeoutExpired:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["output"] = "Proof generation timed out (>1 hour)."
    except Exception as exc:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["output"] = str(exc)


# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# BBS Signatures
# ---------------------------------------------------------------------------


@app.route("/bbs")
def bbs_index():
    return render_template("bbs/index.html")


@app.route("/bbs/issue", methods=["GET", "POST"])
def bbs_issue():
    if request.method == "POST":
        # Fixed attributes — the user just "obtains" a credential
        issuer = "ExampleOrg"
        policy = "issuance-policy-v1"
        user_id = "user-1234"
        device_id = "device-9876"

        cred_path = unique_path(UPLOAD_DIR, ".json")
        result = run_cli([
            str(BBS_BIN / "c2pa-bbs-issue"),
            "--output", str(cred_path),
            "--issuer", issuer,
            "--policy", policy,
            "--user-id", user_id,
            "--device-id", device_id,
        ])

        if result.returncode != 0:
            flash(f"Failed to obtain credential: {result.stderr}", "error")
            return render_template("bbs/issue.html", wallet=wallet)

        # Store in wallet
        cred_data = json.loads(cred_path.read_text())
        wallet.append({
            "id": len(wallet) + 1,
            "issuer": cred_data["public_attributes"]["issuer"],
            "policy": cred_data["public_attributes"]["policy"],
            "path": str(cred_path),
            "data": cred_data,
        })

        return render_template(
            "bbs/issue.html",
            success=True,
            wallet=wallet,
        )

    return render_template("bbs/issue.html", wallet=wallet)


@app.route("/bbs/wallet/clear", methods=["POST"])
def bbs_clear_wallet():
    wallet.clear()
    flash("Wallet cleared.", "success")
    return redirect(url_for("bbs_issue"))


@app.route("/bbs/sign", methods=["GET", "POST"])
def bbs_sign():
    if request.method == "POST":
        cred_idx = request.form.get("credential_idx", "")

        input_path = resolve_input_image(BBS_FIXTURES)
        if not input_path:
            flash("Please upload or select an image.", "error")
            return render_template("bbs/sign.html", wallet=wallet)

        # Resolve credential from wallet
        try:
            idx = int(cred_idx) - 1
            cred_entry = wallet[idx]
        except (ValueError, IndexError):
            flash("No credential selected. Obtain one first.", "error")
            return render_template("bbs/sign.html", wallet=wallet)

        output_path = unique_path(UPLOAD_DIR, input_path.suffix)

        result = run_cli([
            str(BBS_BIN / "c2pa-bbs-sign"),
            "--input", str(input_path),
            "--output", str(output_path),
            "--credential", cred_entry["path"],
        ])

        if result.returncode != 0:
            flash(f"Signing failed: {result.stderr}", "error")
            return render_template("bbs/sign.html", wallet=wallet)

        return render_template(
            "bbs/sign.html",
            success=True,
            output_filename=output_path.name,
            wallet=wallet,
        )

    return render_template("bbs/sign.html", wallet=wallet)


@app.route("/bbs/verify", methods=["GET", "POST"])
def bbs_verify():
    if request.method == "POST":
        image = request.files.get("image")
        if not image or not allowed_file(image.filename):
            flash("Please upload a signed PNG or JPEG image.", "error")
            return render_template("bbs/verify.html")

        suffix = Path(image.filename).suffix
        input_path = unique_path(UPLOAD_DIR, suffix)
        image.save(str(input_path))

        result = run_cli([
            str(BBS_BIN / "c2pa-bbs-verify"),
            "--input", str(input_path),
        ])

        verified = result.returncode == 0
        output = result.stdout + result.stderr
        return render_template(
            "bbs/verify.html",
            verified=verified,
            output=output.strip(),
            input_filename=input_path.name,
        )

    return render_template("bbs/verify.html")


# ---------------------------------------------------------------------------
# ZK Proofs
# ---------------------------------------------------------------------------


@app.route("/zk")
def zk_index():
    return render_template("zk/index.html")


@app.route("/zk/sign", methods=["GET", "POST"])
def zk_sign():
    if request.method == "POST":
        input_path = resolve_input_image(ZK_FIXTURES)
        if not input_path:
            flash("Please upload or select an image.", "error")
            return render_template("zk/sign.html")

        output_path = unique_path(UPLOAD_DIR, input_path.suffix)

        result = run_cli([
            str(ZK_BIN / "c2pa-x509-zk-sign"),
            "--input", str(input_path),
            "--output", str(output_path),
            "--cert", str(ZK_CERTS / "signer-cert.pem"),
            "--key", str(ZK_CERTS / "signer-key.pem"),
            "--ca", str(ZK_CERTS / "ca-cert.pem"),
        ])

        if result.returncode != 0:
            flash(f"Signing failed: {result.stderr}", "error")
            return render_template("zk/sign.html")

        return render_template(
            "zk/sign.html",
            success=True,
            output=result.stdout.strip(),
            output_filename=output_path.name,
        )

    return render_template("zk/sign.html")


@app.route("/zk/anonymize", methods=["GET", "POST"])
def zk_anonymize():
    if request.method == "POST":
        image = request.files.get("image")
        use_placeholder = "placeholder" in request.form

        if not image or not allowed_file(image.filename):
            flash("Please upload a signed PNG or JPEG image.", "error")
            return render_template("zk/anonymize.html")

        suffix = Path(image.filename).suffix
        input_path = unique_path(UPLOAD_DIR, suffix)
        output_path = unique_path(UPLOAD_DIR, suffix)
        image.save(str(input_path))

        cmd = [
            str(ZK_BIN / "c2pa-x509-zk-anonymizer"),
            "--input", str(input_path),
            "--output", str(output_path),
            "--ca", str(ZK_CERTS / "ca-cert.pem"),
            "--signer-key", str(ZK_CERTS / "signer-key.pem"),
            "--cert", str(ZK_CERTS / "signer-cert.pem"),
            "--circuits-dir", str(ZK_CIRCUITS),
        ]
        if use_placeholder:
            cmd.append("--placeholder")

        # Placeholder mode runs synchronously (fast)
        if use_placeholder:
            result = run_cli(cmd, cwd=str(ROOT / "zk-proofs"))
            if result.returncode != 0:
                flash(f"Anonymization failed: {result.stderr}", "error")
                return render_template("zk/anonymize.html")
            return render_template(
                "zk/anonymize.html",
                success=True,
                output=(result.stdout + result.stderr).strip(),
                output_filename=output_path.name,
            )

        # Real ZK proof: run in background thread
        job_id = uuid.uuid4().hex
        jobs[job_id] = {"status": "queued", "started": None, "output": "",
                        "output_filename": None, "elapsed": None}
        thread = threading.Thread(
            target=run_cli_background,
            args=(job_id, cmd, output_path.name),
            kwargs={"cwd": str(ROOT / "zk-proofs")},
            daemon=True,
        )
        thread.start()
        return redirect(url_for("zk_anonymize_status", job_id=job_id))

    return render_template("zk/anonymize.html")


@app.route("/zk/anonymize/status/<job_id>")
def zk_anonymize_status(job_id: str):
    """Page that polls for job completion."""
    job = jobs.get(job_id)
    if not job:
        flash("Unknown job.", "error")
        return redirect(url_for("zk_anonymize"))
    return render_template("zk/anonymize_progress.html", job_id=job_id, job=job)


@app.route("/api/job/<job_id>")
def job_status_api(job_id: str):
    """JSON endpoint for polling job status."""
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404
    elapsed = None
    if job["started"]:
        elapsed = job["elapsed"] or int(time.time() - job["started"])
    return jsonify({
        "status": job["status"],
        "elapsed": elapsed,
        "output": job.get("output", ""),
        "output_filename": job.get("output_filename"),
    })


@app.route("/zk/verify", methods=["GET", "POST"])
def zk_verify():
    if request.method == "POST":
        image = request.files.get("image")
        if not image or not allowed_file(image.filename):
            flash("Please upload an anonymized PNG or JPEG image.", "error")
            return render_template("zk/verify.html")

        suffix = Path(image.filename).suffix
        input_path = unique_path(UPLOAD_DIR, suffix)
        image.save(str(input_path))

        result = run_cli([
            str(ZK_BIN / "c2pa-x509-zk-verify"),
            "--input", str(input_path),
            "--ca", str(ZK_CERTS / "ca-cert.pem"),
            "--circuits-dir", str(ZK_CIRCUITS),
        ], cwd=str(ROOT / "zk-proofs"))

        verified = result.returncode == 0
        output = result.stdout + result.stderr
        return render_template(
            "zk/verify.html",
            verified=verified,
            output=output.strip(),
            input_filename=input_path.name,
        )

    return render_template("zk/verify.html")


# ---------------------------------------------------------------------------
# File downloads
# ---------------------------------------------------------------------------


@app.route("/download/<filename>")
def download_file(filename: str):
    # Prevent path traversal
    safe_name = Path(filename).name
    if safe_name != filename:
        return "Invalid filename", 400
    filepath = UPLOAD_DIR / safe_name
    if not filepath.exists():
        return "File not found", 404
    return send_from_directory(str(UPLOAD_DIR), safe_name, as_attachment=True)


@app.route("/preview/<filename>")
def preview_file(filename: str):
    """Serve uploaded images inline for preview (not as download)."""
    safe_name = Path(filename).name
    if safe_name != filename:
        return "Invalid filename", 400
    filepath = UPLOAD_DIR / safe_name
    if not filepath.exists():
        return "File not found", 404
    return send_from_directory(str(UPLOAD_DIR), safe_name)


# ---------------------------------------------------------------------------
# Sample image endpoint
# ---------------------------------------------------------------------------


@app.route("/sample/<path:name>")
def sample_image(name: str):
    """Serve fixture images (cards.png) for convenience."""
    safe_name = Path(name).name
    if safe_name != name:
        return "Invalid filename", 400
    # Try BBS fixtures first, then ZK
    for d in [BBS_FIXTURES, ZK_FIXTURES]:
        p = d / safe_name
        if p.exists():
            return send_from_directory(str(d), safe_name)
    return "Not found", 404


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Temp directory: {UPLOAD_DIR}")
    print(f"BBS binaries:   {BBS_BIN}")
    print(f"ZK binaries:    {ZK_BIN}")
    app.run(debug=True, host="127.0.0.1", port=5000)
