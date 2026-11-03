//! Benchmark harness (roadmap F2).
//!
//! `c2pa-x509-zk-bench run` measures the current statement end to end on fixed
//! inputs and writes one JSON record. Each phase (compile, setup, witness,
//! prove, verify) runs as a separate subprocess of this binary, so its wall
//! time and peak memory are its own (`wait4` resource usage of that process);
//! loading and serialization steps inside a phase are timed separately and
//! reported with it, so no cost falls between phases.
//!
//! Everything happens in a private work directory: the harness compiles (or,
//! with --reuse-build, links) the circuit there and generates its own keys,
//! leaving circuits/build untouched.
//!
//! Usage:
//!   c2pa-x509-zk-bench run [--reuse-build] [--keep] [--out results.json]
//!
//! Peak memory comes from the child's ru_maxrss, in KiB on Linux.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use c2pa_x509_zk_demo::{
    check_witness, circuit, circuit_builder, compute_manifest_stripped_asset_digest, compute_witness, extract_issuer_dn,
    issuing_path_for, load_proving_key, load_r1cs, load_verifying_key,
    manifest::{extract_manifest_data, rewrite_manifest_with_zk_proof},
    native_setup, prove_circuit, read_witness, spki_key_id, verify_proof_native, write_witness, CircuitInputs,
    NativeCircuitPaths, NativeProof, TrustList, X509ZkSignerProofAssertion,
};

const CIRCUIT: &str = "x509_issue_and_possession";
const RESULT_PREFIX: &str = "BENCH-RESULT ";

/// The statement the current circuit proves, recorded with every result.
const STATEMENT: &str = "Signer-side anonymization, trust model A: the issuing CA's P-256 key (a public input) \
signed, with ECDSA-SHA256, a certificate whose P-256 subject key (pinned inside the signed TBSCertificate) \
signed the manifest-stripped asset digest (a public input), and the certificate's validity period (also pinned) \
contains a prover-chosen timestamp (a public input the verifier does not check). Off-circuit, the issuing CA chain \
in x5chain is validated against a trust list.";

#[derive(Parser)]
#[command(name = "c2pa-x509-zk-bench", about = "Benchmark the ZK anonymizer (roadmap F2)")]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run every phase and write a JSON record
    Run {
        /// Work directory (default: target/bench/<unix time>)
        #[arg(long)]
        work_dir: Option<PathBuf>,
        /// Circom circuits directory (sources, and the build to reuse)
        #[arg(long, default_value = "circuits")]
        circuits_dir: PathBuf,
        /// Link circuits/build's compiled circuit instead of compiling (compile is then not measured)
        #[arg(long)]
        reuse_build: bool,
        /// Keep the work directory (circuit, keys, witness) after the run
        #[arg(long)]
        keep: bool,
        /// Write the JSON record here (default: stdout)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Internal: run one phase in this process (used by `run`)
    #[command(hide = true)]
    Phase {
        name: String,
        #[arg(long)]
        work_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    match Args::parse().command {
        Cmd::Run { work_dir, circuits_dir, reuse_build, keep, out } => run(work_dir, &circuits_dir, reuse_build, keep, out),
        Cmd::Phase { name, work_dir } => {
            // wasmer (witness generation) needs a Tokio runtime.
            tokio::runtime::Runtime::new()?.block_on(async { phase(&name, &work_dir) })
        }
    }
}

fn paths(work_dir: &Path) -> NativeCircuitPaths {
    NativeCircuitPaths::default_for_circuit(work_dir, CIRCUIT)
}

/// Time a step and record it in `steps`.
fn timed<T>(steps: &mut serde_json::Map<String, Value>, name: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let start = Instant::now();
    let value = f()?;
    steps.insert(format!("{name}_s"), json!(start.elapsed().as_secs_f64()));
    Ok(value)
}

/// One phase, run inside a subprocess. Prints a `BENCH-RESULT` JSON line.
fn phase(name: &str, work_dir: &Path) -> Result<()> {
    let paths = paths(work_dir);
    let mut steps = serde_json::Map::new();
    let mut data = serde_json::Map::new();
    match name {
        "setup" => {
            timed(&mut steps, "setup", || native_setup(&paths))?;
            data.insert("proving_key_bytes".into(), json!(std::fs::metadata(&paths.proving_key)?.len()));
            data.insert("verifying_key_bytes".into(), json!(std::fs::metadata(&paths.verifying_key)?.len()));
        }
        "witness" => {
            let inputs: CircuitInputs =
                timed(&mut steps, "read_inputs", || Ok(serde_json::from_slice(&std::fs::read(work_dir.join("inputs.json"))?)?))?;
            // The steps of compute_checked_witness, timed separately.
            let builder = timed(&mut steps, "load_circuit", || circuit_builder(&inputs, &paths))?;
            let circuit = timed(&mut steps, "compute_witness", || compute_witness(builder))?;
            timed(&mut steps, "check_witness", || check_witness(&circuit))?;
            let witness = circuit.witness.as_ref().ok_or_else(|| anyhow!("no witness"))?;
            data.insert("constraints".into(), json!(circuit.r1cs.constraints.len()));
            data.insert("wires".into(), json!(witness.len()));
            timed(&mut steps, "write_witness", || write_witness(&work_dir.join("witness.bin"), witness))?;
        }
        "prove" => {
            let r1cs = timed(&mut steps, "load_r1cs", || load_r1cs(&paths.r1cs))?;
            let witness = timed(&mut steps, "read_witness", || read_witness(&work_dir.join("witness.bin")))?;
            let pk = timed(&mut steps, "load_proving_key", || load_proving_key(&paths.proving_key))?;
            let circuit = ark_circom::CircomCircuit { r1cs, witness: Some(witness) };
            let proof = timed(&mut steps, "prove", || prove_circuit(circuit, &pk))?;
            timed(&mut steps, "write_proof", || Ok(std::fs::write(work_dir.join("proof.b64"), proof.to_base64()?)?))?;
        }
        "verify" => {
            let proof = timed(&mut steps, "read_proof", || NativeProof::from_base64(&std::fs::read_to_string(work_dir.join("proof.b64"))?))?;
            // verify_proof_native loads and processes the verifying key itself; time loading separately too.
            timed(&mut steps, "load_verifying_key", || load_verifying_key(&paths.verifying_key).map(|_| ()))?;
            let valid = timed(&mut steps, "load_and_verify", || verify_proof_native(&proof, &paths))?;
            if !valid {
                bail!("proof did not verify");
            }
        }
        other => bail!("unknown phase {other}"),
    }
    println!("{RESULT_PREFIX}{}", json!({ "steps": steps, "data": data }));
    Ok(())
}

/// A subprocess's wall time, peak memory, and parsed BENCH-RESULT line.
struct Measured {
    wall_s: f64,
    peak_rss_kib: i64,
    result: Option<Value>,
}

/// Run `cmd` to completion and measure it with wait4 (its own peak RSS).
fn run_measured(cmd: &mut Command) -> Result<Measured> {
    cmd.stdout(Stdio::piped());
    let start = Instant::now();
    let mut child = cmd.spawn().with_context(|| format!("failed to start {cmd:?}"))?;
    let mut stdout = String::new();
    child.stdout.take().unwrap().read_to_string(&mut stdout)?;

    let mut status = 0;
    // SAFETY: rusage is plain data; wait4 fills it for the child we spawned.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::wait4(child.id() as libc::pid_t, &mut status, 0, &mut usage) } < 0 {
        bail!("wait4 failed: {}", std::io::Error::last_os_error());
    }
    let wall_s = start.elapsed().as_secs_f64();
    if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
        eprintln!("{stdout}");
        bail!("{cmd:?} failed (wait status {status})");
    }
    let result = stdout
        .lines()
        .find_map(|l| l.strip_prefix(RESULT_PREFIX))
        .map(serde_json::from_str)
        .transpose()?;
    Ok(Measured { wall_s, peak_rss_kib: usage.ru_maxrss, result })
}

fn phase_record(name: &str, m: &Measured) -> Value {
    let result = m.result.clone().unwrap_or(json!({}));
    json!({
        "name": name,
        "wall_s": m.wall_s,
        "peak_rss_mib": m.peak_rss_kib as f64 / 1024.0,
        "steps": result["steps"],
        "data": result["data"],
    })
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn proc_field(path: &str, key: &str) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with(key)).map(|l| l.split_once(':').map_or(l, |x| x.1).trim().to_string()))
        .unwrap_or_else(|| "unknown".into())
}

fn environment(zk_root: &Path) -> Value {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string();
    let os = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string())))
        .unwrap_or_else(|| "unknown".into());
    let repo = zk_root.to_str().unwrap_or(".");
    // Tracked files that differ from the commit, excluding generated circuit
    // artifacts (keys in circuits/build), which the harness does not use.
    let changed: Vec<String> = command_output("git", &["-C", repo, "status", "--porcelain", "--untracked-files=no", "--", ".", ":!circuits/build"])
        .lines()
        .filter(|l| !l.is_empty() && *l != "unknown")
        .map(|l| l.trim().to_string())
        .collect();
    json!({
        "cpu": proc_field("/proc/cpuinfo", "model name"),
        "logical_cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "memory": proc_field("/proc/meminfo", "MemTotal"),
        "os": os,
        "kernel": kernel,
        "wsl": kernel.to_lowercase().contains("microsoft"),
        "rustc": command_output("rustc", &["--version"]),
        "circom": command_output("circom", &["--version"]),
        "git_commit": command_output("git", &["-C", repo, "rev-parse", "HEAD"]),
        "git_changed_files": changed,
        "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
    })
}

/// Decode a PEM private key (SEC1 "EC PRIVATE KEY" or PKCS#8) to DER.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    Ok(base64::engine::general_purpose::STANDARD.decode(b64)?)
}

fn run(work_dir: Option<PathBuf>, circuits_dir: &Path, reuse_build: bool, keep: bool, out: Option<PathBuf>) -> Result<()> {
    let zk_root = std::env::current_dir()?;
    let exe = std::env::current_exe()?;
    let bin_dir = exe.parent().unwrap().to_path_buf();
    let work_dir = work_dir.unwrap_or_else(|| {
        zk_root.join("target/bench").join(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs().to_string())
    });
    let build = work_dir.join("build");
    std::fs::create_dir_all(&build)?;
    let circuits_dir = std::fs::canonicalize(circuits_dir)?;
    eprintln!("Work directory: {}", work_dir.display());

    // ---- Fixed inputs: a generated test PKI and a signed sample asset -------
    let pki = work_dir.join("pki");
    let ok = Command::new("bash").arg(zk_root.join("generate-test-pki.sh")).arg(&pki).arg("Bench")
        .stdout(Stdio::null()).stderr(Stdio::null()).status()?.success();
    if !ok {
        bail!("generate-test-pki.sh failed");
    }
    let asset = zk_root.join("fixtures/cards.png");
    let signed = work_dir.join("signed.png");
    let ok = Command::new(bin_dir.join("c2pa-x509-zk-sign"))
        .args(["--input"]).arg(&asset).args(["--output"]).arg(&signed)
        .args(["--cert"]).arg(pki.join("signer.pem")).args(["--key"]).arg(pki.join("signer.key"))
        .args(["--ca"]).arg(pki.join("issuing-ca.pem"))
        .stdout(Stdio::null()).status()?.success();
    if !ok {
        bail!("signing failed");
    }

    let trust = TrustList::from_file(&pki.join("trust-list.pem"))?;
    let manifest_data = extract_manifest_data(&signed)?;
    let issuing_chain = issuing_path_for(&manifest_data.leaf_cert_der, &manifest_data.ca_certs_der, &trust, manifest_data.photo_timestamp)?;
    let signer_key = pem_to_der(&std::fs::read_to_string(pki.join("signer.key"))?)?;
    let proof_inputs = circuit::prepare_inputs(&manifest_data, &signer_key, &issuing_chain[0])?;
    let inputs = circuit::proof_inputs_to_circuit(&proof_inputs)?;
    std::fs::write(work_dir.join("inputs.json"), serde_json::to_vec(&inputs)?)?;
    let tbs_len: usize = inputs.tbs_len.parse()?;

    // ---- Phases, each in its own subprocess --------------------------------
    let mut phases = Vec::new();
    let circuit_src = circuits_dir.join(format!("{CIRCUIT}.circom"));
    if reuse_build {
        let source_build = circuits_dir.join("build");
        std::os::unix::fs::symlink(source_build.join(format!("{CIRCUIT}.r1cs")), build.join(format!("{CIRCUIT}.r1cs")))?;
        std::os::unix::fs::symlink(source_build.join(format!("{CIRCUIT}_js")), build.join(format!("{CIRCUIT}_js")))?;
        phases.push(json!({ "name": "compile", "skipped": "reused circuits/build" }));
    } else {
        eprintln!("Compiling the circuit...");
        let m = run_measured(
            Command::new("circom").arg(&circuit_src).args(["--r1cs", "--wasm", "-l"]).arg(&circuits_dir)
                .arg("-l").arg(circuits_dir.join("node_modules")).arg("-o").arg(&build),
        )?;
        phases.push(phase_record("compile", &m));
    }
    for name in ["setup", "witness", "prove", "verify"] {
        eprintln!("Phase: {name}...");
        let m = run_measured(Command::new(&exe).args(["phase", name, "--work-dir"]).arg(&work_dir))?;
        phases.push(phase_record(name, &m));
    }

    // ---- Package the anonymized asset and check it with the verifier CLI ---
    let paths = paths(&work_dir);
    let build_manifest = paths.read_build_manifest()?.ok_or_else(|| anyhow!("setup wrote no build manifest"))?;
    let proof_b64 = std::fs::read_to_string(work_dir.join("proof.b64"))?;
    let proof = NativeProof::from_base64(&proof_b64)?;
    let assertion = X509ZkSignerProofAssertion::new(
        extract_issuer_dn(&manifest_data.leaf_cert_der)?,
        spki_key_id(&issuing_chain[0])?,
        hex::encode(&manifest_data.claim_hash),
        proof_b64.clone(),
    )
    .with_artifacts(&build_manifest);
    let anonymized = work_dir.join("anon.png");
    rewrite_manifest_with_zk_proof(&signed, &anonymized, assertion.clone(), issuing_chain.clone())?;
    if hex::encode(compute_manifest_stripped_asset_digest(&anonymized)?) != assertion.claim_hash {
        bail!("anonymized asset digest does not match the proof");
    }
    eprintln!("Phase: verify (CLI, full anonymized-asset verification)...");
    let m = run_measured(
        Command::new(bin_dir.join("c2pa-x509-zk-verify")).arg("--input").arg(&anonymized)
            .arg("--trust-list").arg(pki.join("trust-list.pem")).arg("--circuits-dir").arg(&work_dir),
    )?;
    phases.push(phase_record("verify_cli", &m));

    // Manifest store size: the anonymized file minus the same file with its JUMBF removed.
    let stripped = work_dir.join("stripped.png");
    std::fs::copy(&anonymized, &stripped)?;
    c2pa::jumbf_io::remove_jumbf_from_file(&stripped).map_err(|e| anyhow!("failed to strip manifest: {e}"))?;
    let mut groth16 = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof.proof, &mut groth16)?;

    let record = json!({
        "schema": "c2pa-x509-zk-bench/1",
        "variant": {
            "mode": "signer-side",
            "trust_model": "A",
            "signer_key": "P-256",
            "ca_signature": "ECDSA P-256 with SHA-256",
            "proof_system": "Groth16 (ark-groth16, ark-circom witness generation in WASM)",
            "curve": "BN254",
            "circuit": CIRCUIT,
        },
        "statement": STATEMENT,
        "environment": environment(&zk_root),
        "artifacts": {
            "r1cs_sha256": build_manifest.r1cs_sha256,
            "verifying_key_sha256": build_manifest.verifying_key_sha256,
            "r1cs_bytes": std::fs::metadata(&paths.r1cs)?.len(),
            "wasm_bytes": std::fs::metadata(&paths.wasm)?.len(),
        },
        "inputs": {
            "signer_certificate_bytes": manifest_data.leaf_cert_der.len(),
            "tbs_certificate_bytes": tbs_len + 4,
            "issuing_chain_certificates": issuing_chain.len(),
            "asset_bytes": std::fs::metadata(&asset)?.len(),
        },
        "phases": phases,
        "output": {
            "groth16_proof_bytes": groth16.len(),
            "public_inputs": proof.public_inputs.len(),
            "proof_container_bytes": proof_b64.len(),
            "assertion_json_bytes": serde_json::to_vec(&assertion)?.len(),
            "x5chain_bytes": issuing_chain.iter().map(Vec::len).sum::<usize>(),
            "manifest_store_bytes": std::fs::metadata(&anonymized)?.len() - std::fs::metadata(&stripped)?.len(),
            "note": "manifest_store_bytes is the whole C2PA store added to the asset, including the COSE signature's \
                     reserved padding; proof_container_bytes is the proof as embedded (base64 of JSON with the \
                     public inputs); the COSE signature field holds the same container decoded once.",
        },
    });

    let text = serde_json::to_string_pretty(&record)?;
    match out {
        Some(path) => std::fs::write(&path, text + "\n")?,
        None => println!("{text}"),
    }
    eprintln!("\nPhase              wall (s)   peak RSS (MiB)");
    for p in record["phases"].as_array().unwrap() {
        match (p["wall_s"].as_f64(), p["peak_rss_mib"].as_f64()) {
            (Some(w), Some(r)) => eprintln!("{:<18} {:>8.1}   {:>14.0}", p["name"].as_str().unwrap(), w, r),
            _ => eprintln!("{:<18} {}", p["name"].as_str().unwrap(), p["skipped"].as_str().unwrap_or("")),
        }
    }
    if !keep {
        std::fs::remove_dir_all(&work_dir)?;
    }
    Ok(())
}
