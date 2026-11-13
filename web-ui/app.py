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
# The web demo's own PKI: the mirror profile (P-384 CAs, a P-256 signer, a local TSA).
ZK_PKI = ZK_FIXTURES / "web-pki"
# The statements' key directories (override with C2PA_ZK_KEYS_ROOT).
ZK_KEYS_ROOT = Path(os.environ.get("C2PA_ZK_KEYS_ROOT", ROOT / "zk-proofs" / "target"))

UPLOAD_DIR = Path(tempfile.mkdtemp(prefix="c2pa_web_"))
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

# Background jobs for long-running operations (ZK proof generation)
jobs: dict[str, dict] = {}
# One proof at a time: each needs up to ~9 GB.
proof_lock = threading.Lock()

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


def ensure_zk_pki() -> None:
    """Create the ZK test PKI if there is none, and renew the signer
    certificate (same key, same trust anchors) when it expires within a day.

    Never replaces the trust anchors, which would make every previously
    anonymized asset untrusted: a full reset is a manual run of
    zk-proofs/generate-test-pki.sh.
    """
    script = ROOT / "zk-proofs" / "generate-test-pki.sh"
    if not (ZK_PKI / "trust-list.pem").exists():
        subprocess.run(["bash", str(script), "--mirror", str(ZK_PKI), "Web Demo"], check=True, capture_output=True)
        return
    expiring = subprocess.run(
        ["openssl", "x509", "-checkend", "86400", "-noout", "-in", str(ZK_PKI / "signer.pem")],
        capture_output=True,
    ).returncode != 0
    if expiring:
        subprocess.run(["bash", str(script), "--renew-signer", "--mirror", str(ZK_PKI)], check=True, capture_output=True)


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
    with proof_lock:
        _run_job(job_id, args, output_filename, cwd)


def _run_job(job_id: str, args: list[str], output_filename: str, cwd: str | None) -> None:
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
            jobs[job_id]["output"] = (result.stdout + result.stderr).strip()
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
# ZK Proofs (Milestone 1: third-party anonymization in gnark)
# ---------------------------------------------------------------------------

# The anonymization modes, each with the key directory of its statement
# (from `c2pa-zk-gnark setup`, see zk-proofs/REPRODUCING.md#keys).
ZK_MODES = {
    "disclosed": {
        "label": "Disclosed issuer",
        "keys": ZK_KEYS_ROOT / "gnark-keys",
        "setup": "./target/c2pa-zk-gnark setup --keys target/gnark-keys",
    },
    "hidden-issuer": {
        "label": "Hidden issuer",
        "keys": ZK_KEYS_ROOT / "gnark-keys-hidden",
        "setup": "./target/c2pa-zk-gnark setup --keys target/gnark-keys-hidden --statement hidden-issuer",
    },
    "hidden-all": {
        "label": "Hidden issuer and time stamp",
        "keys": ZK_KEYS_ROOT / "gnark-keys-hidden-all",
        "setup": "./target/c2pa-zk-gnark setup --keys target/gnark-keys-hidden-all --statement hidden-all",
    },
}
# The names the anonymizer writes into hidden-issuer assets as hints, and the
# verifier's policy approving them (the demo PKI's lists, from its creation).
ISSUER_LIST_NAME = "web-demo-list"
TSA_LIST_NAME = "web-demo-tsa"
TIME_WINDOWS = {"1h": "1 hour", "1d": "1 day (UTC)"}
MAX_TIME_WINDOW = 86400


def issuer_policy() -> Path:
    """The verifier's policy for assets hiding their issuer (and time stamp)."""
    path = UPLOAD_DIR / "issuer-policy.json"
    path.write_text(json.dumps({
        "snapshots": [{"name": ISSUER_LIST_NAME, "trust_list": str(ZK_PKI / "trust-list.pem"), "from": 0}],
        "tsa_snapshots": [{"name": TSA_LIST_NAME, "trust_list": str(ZK_PKI / "tsa-trust-list.pem"), "from": 0}],
        "max_time_window": MAX_TIME_WINDOW,
    }))
    return path


def zk_modes_view() -> list[dict]:
    return [{"id": k, "label": m["label"], "ready": (m["keys"] / "statement.pk").exists(),
             "setup": m["setup"]} for k, m in ZK_MODES.items()]


@app.route("/zk")
def zk_index():
    return render_template("zk/index.html", modes=zk_modes_view())


@app.route("/zk/sign", methods=["GET", "POST"])
def zk_sign():
    if request.method == "POST":
        ensure_zk_pki()
        input_path = resolve_input_image(ZK_FIXTURES)
        if not input_path:
            flash("Please upload or select an image.", "error")
            return render_template("zk/sign.html")

        output_path = unique_path(UPLOAD_DIR, input_path.suffix)

        # Signed and time-stamped (sigTst2, by a local TSA), as on a real device.
        result = run_cli([
            str(ZK_BIN / "c2pa-x509-zk-sign"),
            "--input", str(input_path),
            "--output", str(output_path),
            "--cert", str(ZK_PKI / "signer.pem"),
            "--key", str(ZK_PKI / "signer.key"),
            "--ca", str(ZK_PKI / "issuing-ca.pem"),
            "--tsa-cert", str(ZK_PKI / "tsa.pem"),
            "--tsa-key", str(ZK_PKI / "tsa.key"),
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
    view = {"modes": zk_modes_view(), "time_windows": TIME_WINDOWS}
    if request.method == "POST":
        ensure_zk_pki()
        image = request.files.get("image")
        mode_id = request.form.get("mode", "disclosed")
        window = request.form.get("time_window", "1d")
        scrub = "scrub_metadata" in request.form

        if not image or not allowed_file(image.filename):
            flash("Please upload a signed PNG or JPEG image.", "error")
            return render_template("zk/anonymize.html", **view)
        mode = ZK_MODES.get(mode_id)
        if mode is None or window not in TIME_WINDOWS:
            flash("Unknown mode or time window.", "error")
            return render_template("zk/anonymize.html", **view)
        if not (mode["keys"] / "statement.pk").exists():
            flash(f"No keys for this mode in {mode['keys']}. Run once, from zk-proofs/: {mode['setup']}", "error")
            return render_template("zk/anonymize.html", **view)

        suffix = Path(image.filename).suffix
        input_path = unique_path(UPLOAD_DIR, suffix)
        output_path = unique_path(UPLOAD_DIR, suffix)
        image.save(str(input_path))

        cmd = [
            str(ZK_BIN / "c2pa-x509-zk-anonymizer"), "--third-party",
            "--keys", str(mode["keys"]),
            "--input", str(input_path),
            "--output", str(output_path),
            "--trust-list", str(ZK_PKI / "trust-list.pem"),
        ]
        if mode_id in ("hidden-issuer", "hidden-all"):
            cmd += ["--hide-issuer", ISSUER_LIST_NAME]
        if mode_id == "hidden-all":
            cmd += ["--hide-time-stamp", TSA_LIST_NAME,
                    "--tsa-trust-list", str(ZK_PKI / "tsa-trust-list.pem"),
                    "--time-window", window]
        if scrub:
            cmd.append("--scrub-metadata")

        # Proving takes 1.5-2.5 minutes and up to ~9 GB: run in the background,
        # one proof at a time.
        job_id = uuid.uuid4().hex
        jobs[job_id] = {"status": "queued", "started": None, "output": "",
                        "output_filename": None, "elapsed": None,
                        "mode": mode["label"]}
        thread = threading.Thread(
            target=run_cli_background,
            args=(job_id, cmd, output_path.name),
            kwargs={"cwd": str(ROOT / "zk-proofs")},
            daemon=True,
        )
        thread.start()
        return redirect(url_for("zk_anonymize_status", job_id=job_id))

    return render_template("zk/anonymize.html", **view)


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
        # Verification only reads the trust lists; it never creates or renews keys.
        if not (ZK_PKI / "trust-list.pem").exists():
            flash("No test PKI yet: sign an image first.", "error")
            return render_template("zk/verify.html")
        image = request.files.get("image")
        if not image or not allowed_file(image.filename):
            flash("Please upload an anonymized PNG or JPEG image.", "error")
            return render_template("zk/verify.html")

        suffix = Path(image.filename).suffix
        input_path = unique_path(UPLOAD_DIR, suffix)
        image.save(str(input_path))

        # The asset says which statement it uses; the verifier refuses keys
        # for another one before any other check, so try each mode's keys.
        result = None
        for mode in ZK_MODES.values():
            if not (mode["keys"] / "statement.vk").exists():
                continue
            result = run_cli([
                str(ZK_BIN / "c2pa-x509-zk-verify"),
                "--input", str(input_path),
                "--keys", str(mode["keys"]),
                "--trust-list", str(ZK_PKI / "trust-list.pem"),
                "--tsa-trust-list", str(ZK_PKI / "tsa-trust-list.pem"),
                "--issuer-policy", str(issuer_policy()),
            ], cwd=str(ROOT / "zk-proofs"))
            if "the asset is for" not in result.stderr:
                break
        if result is None:
            flash("No verifying keys found: see zk-proofs/REPRODUCING.md#keys.", "error")
            return render_template("zk/verify.html")

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
