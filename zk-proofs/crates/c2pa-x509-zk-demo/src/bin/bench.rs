//! Benchmark harness (roadmap F2).
//!
//! `c2pa-x509-zk-bench run` measures the current statement end to end on fixed
//! inputs and writes one JSON record. Every phase runs as a separate
//! subprocess of this binary (or of circom), so its wall time and peak memory
//! are its own (`wait4` resource usage of that process); steps inside a phase
//! are timed separately and reported with it, so no cost falls between
//! phases.
//!
//! Phases and their accounting categories:
//!
//! | Phase    | Category          | Work                                                         |
//! |----------|-------------------|--------------------------------------------------------------|
//! | fixtures | test-fixture      | generate the test PKI, sign the sample asset                 |
//! | compile  | one-time          | compile the circuit (circom)                                 |
//! | setup    | one-time          | Groth16 setup                                                |
//! | prepare  | anonymization     | read the signed manifest, validate the chain, build inputs   |
//! | witness  | anonymization     | load the circuit, compute and check the witness              |
//! | prove    | anonymization     | load R1CS, witness, and proving key; prove                   |
//! | package  | anonymization     | build the assertion, rewrite the manifest, check the digest  |
//! | verify   | verification      | load and prepare the verifying key, verify the proof         |
//! | verify_cli | verification-full | the verifier CLI on the anonymized asset (trust list, checks, proof) |
//!
//! The harness works in a directory it creates exclusively (an existing
//! `--work-dir` is refused) and, unless `--keep`, removes only that directory
//! afterwards. `--out` may not point inside it. It compiles (or, with
//! `--reuse-build`, links) the circuit there and generates its own keys,
//! leaving circuits/build untouched.
//!
//! Usage:
//!   c2pa-x509-zk-bench run [--reuse-build] [--keep] [--work-dir NEW_DIR] [--out results.json]
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
    check_witness, circuit, circuit_builder, compute_manifest_stripped_asset_digest, compute_witness,
    extract_issuer_dn, issuing_path_for, load_proving_key, load_r1cs, load_verifying_key,
    manifest::{extract_manifest_data, rewrite_manifest_with_zk_proof},
    native_setup, prepare_verifying_key, prove_circuit, read_witness, spki_key_id, verify_proof_prepared,
    write_witness, CircuitInputs, NativeCircuitPaths, NativeProof, TrustList, X509ZkSignerProofAssertion,
};

const CIRCUIT: &str = "x509_issue_and_possession";
const RESULT_PREFIX: &str = "BENCH-RESULT ";

/// The statement the current circuit proves, recorded with every result.
const STATEMENT: &str = "Signer-side anonymization, trust model A: the issuing CA's P-256 key (a public input) \
signed, with ECDSA-SHA256, a certificate whose P-256 subject key (pinned inside the signed TBSCertificate) \
signed the manifest-stripped asset digest (a public input), and the certificate's validity period (also pinned) \
contains a prover-chosen timestamp (a public input the verifier does not check). Off-circuit, the issuing CA chain \
in x5chain is validated against a trust list.";

/// What each total covers, recorded with every result so variants count the same work.
const ACCOUNTING: &str = "one_time = compile + setup (per circuit and keys). anonymization_per_asset = prepare + \
witness + prove + package: the complete latency of anonymizing one asset, from a signed asset to an anonymized \
one, excluding one-time work; anonymization_witness_plus_prove is the subtotal for proof generation alone. \
verification = loading and preparing the verifying key and verifying the proof; verification_full = the verifier \
CLI on the anonymized asset (trust-list chain validation, assertion and digest checks, and the proof). \
test_fixture (generating the test PKI and signing the sample asset) is not part of any total. Peak memory per \
category is the maximum over its phases, each a separate process.";

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
        /// Work directory to create; must not exist (default: a new directory under target/bench)
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
        /// Write the JSON record here (default: stdout); must be outside the work directory
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Internal: run one phase in this process (used by `run`)
    #[command(hide = true)]
    Phase {
        name: String,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        zk_root: PathBuf,
    },
}

fn main() -> Result<()> {
    match Args::parse().command {
        Cmd::Run { work_dir, circuits_dir, reuse_build, keep, out } => run(work_dir, &circuits_dir, reuse_build, keep, out),
        Cmd::Phase { name, work_dir, zk_root } => {
            // wasmer (witness generation) needs a Tokio runtime.
            tokio::runtime::Runtime::new()?.block_on(async { phase(&name, &work_dir, &zk_root) })
        }
    }
}

// ---- Work directory lifecycle ------------------------------------------------

/// Create the run's work directory exclusively. A requested directory must
/// not exist (its parent is created if needed); otherwise a new uniquely named
/// directory is created under `default_parent`. The run owns, and may later
/// delete, only the directory returned here.
fn create_workspace(requested: Option<&Path>, default_parent: &Path) -> Result<PathBuf> {
    if let Some(dir) = requested {
        let dir = std::path::absolute(dir)?;
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir(&dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow!("--work-dir {} already exists; the harness only uses a directory it creates", dir.display())
            } else {
                anyhow!("failed to create {}: {e}", dir.display())
            }
        })?;
        return Ok(dir);
    }
    let parent = std::path::absolute(default_parent)?;
    std::fs::create_dir_all(&parent)?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    for attempt in 0..1000 {
        let dir = parent.join(format!("run-{stamp}-{}-{attempt}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => bail!("failed to create {}: {e}", dir.display()),
        }
    }
    bail!("could not create a unique work directory under {}", parent.display())
}

/// The output file must not be inside the work directory, which may be deleted.
fn check_output_location(out: Option<&Path>, work_dir: &Path) -> Result<()> {
    if let Some(out) = out {
        if std::path::absolute(out)?.starts_with(work_dir) {
            bail!("--out {} is inside the work directory {}, which is removed after the run", out.display(), work_dir.display());
        }
    }
    Ok(())
}

/// Remove the work directory created by `create_workspace`, unless `keep`.
fn finish_workspace(work_dir: &Path, keep: bool) -> Result<()> {
    if !keep {
        std::fs::remove_dir_all(work_dir)?;
    }
    Ok(())
}

// ---- Phases (each runs in its own subprocess) --------------------------------

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

/// Decode a PEM private key (SEC1 "EC PRIVATE KEY" or PKCS#8) to DER.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    Ok(base64::engine::general_purpose::STANDARD.decode(b64)?)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// One phase, run inside a subprocess. Prints a `BENCH-RESULT` JSON line.
fn phase(name: &str, work_dir: &Path, zk_root: &Path) -> Result<()> {
    let paths = paths(work_dir);
    let pki = work_dir.join("pki");
    let signed = work_dir.join("signed.png");
    let mut steps = serde_json::Map::new();
    let mut data = serde_json::Map::new();
    match name {
        "fixtures" => {
            timed(&mut steps, "generate_pki", || {
                let ok = Command::new("bash").arg(zk_root.join("generate-test-pki.sh")).arg(&pki).arg("Bench")
                    .stdout(Stdio::null()).stderr(Stdio::null()).status()?.success();
                if !ok { bail!("generate-test-pki.sh failed") }
                Ok(())
            })?;
            timed(&mut steps, "sign_asset", || {
                let sign = std::env::current_exe()?.with_file_name("c2pa-x509-zk-sign");
                let ok = Command::new(sign)
                    .arg("--input").arg(zk_root.join("fixtures/cards.png")).arg("--output").arg(&signed)
                    .arg("--cert").arg(pki.join("signer.pem")).arg("--key").arg(pki.join("signer.key"))
                    .arg("--ca").arg(pki.join("issuing-ca.pem"))
                    .stdout(Stdio::null()).status()?.success();
                if !ok { bail!("signing failed") }
                Ok(())
            })?;
        }
        "setup" => {
            timed(&mut steps, "setup", || native_setup(&paths))?;
            data.insert("proving_key_bytes".into(), json!(std::fs::metadata(&paths.proving_key)?.len()));
            data.insert("verifying_key_bytes".into(), json!(std::fs::metadata(&paths.verifying_key)?.len()));
        }
        "prepare" => {
            let trust = timed(&mut steps, "load_trust_list", || TrustList::from_file(&pki.join("trust-list.pem")))?;
            let manifest_data = timed(&mut steps, "read_signed_manifest", || extract_manifest_data(&signed))?;
            let chain = timed(&mut steps, "validate_issuing_chain", || {
                issuing_path_for(&manifest_data.leaf_cert_der, &manifest_data.ca_certs_der, &trust, manifest_data.photo_timestamp)
            })?;
            let inputs = timed(&mut steps, "build_circuit_inputs", || {
                let key = pem_to_der(&std::fs::read_to_string(pki.join("signer.key"))?)?;
                let proof_inputs = circuit::prepare_inputs(&manifest_data, &key, &chain[0])?;
                circuit::proof_inputs_to_circuit(&proof_inputs)
            })?;
            timed(&mut steps, "write_inputs", || {
                std::fs::write(work_dir.join("inputs.json"), serde_json::to_vec(&inputs)?)?;
                let context = json!({
                    "issuer": extract_issuer_dn(&manifest_data.leaf_cert_der)?,
                    "issuer_key_id": spki_key_id(&chain[0])?,
                    "claim_hash": hex::encode(&manifest_data.claim_hash),
                    "issuing_chain": chain.iter().map(|c| b64(c)).collect::<Vec<_>>(),
                });
                Ok(std::fs::write(work_dir.join("context.json"), serde_json::to_vec(&context)?)?)
            })?;
            data.insert("signer_certificate_bytes".into(), json!(manifest_data.leaf_cert_der.len()));
            data.insert("tbs_certificate_bytes".into(), json!(inputs.tbs_len.parse::<usize>()? + 4));
            data.insert("issuing_chain_certificates".into(), json!(chain.len()));
        }
        "witness" => {
            let inputs: CircuitInputs =
                timed(&mut steps, "read_inputs", || Ok(serde_json::from_slice(&std::fs::read(work_dir.join("inputs.json"))?)?))?;
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
        "package" => {
            let context: Value = timed(&mut steps, "read_context", || Ok(serde_json::from_slice(&std::fs::read(work_dir.join("context.json"))?)?))?;
            let proof_b64 = std::fs::read_to_string(work_dir.join("proof.b64"))?;
            let chain = context["issuing_chain"]
                .as_array()
                .ok_or_else(|| anyhow!("context has no issuing chain"))?
                .iter()
                .map(|c| Ok(base64::engine::general_purpose::STANDARD.decode(c.as_str().unwrap_or_default())?))
                .collect::<Result<Vec<Vec<u8>>>>()?;
            let anonymized = work_dir.join("anon.png");
            let assertion = timed(&mut steps, "build_assertion", || {
                let build = paths.read_build_manifest()?.ok_or_else(|| anyhow!("setup wrote no build manifest"))?;
                Ok(X509ZkSignerProofAssertion::new(
                    context["issuer"].as_str().unwrap_or_default().to_string(),
                    context["issuer_key_id"].as_str().unwrap_or_default().to_string(),
                    context["claim_hash"].as_str().unwrap_or_default().to_string(),
                    proof_b64.clone(),
                )
                .with_artifacts(&build))
            })?;
            timed(&mut steps, "rewrite_manifest", || rewrite_manifest_with_zk_proof(&signed, &anonymized, assertion.clone(), chain.clone()))?;
            timed(&mut steps, "check_digest", || {
                if hex::encode(compute_manifest_stripped_asset_digest(&anonymized)?) != assertion.claim_hash {
                    bail!("anonymized asset digest does not match the proof");
                }
                Ok(())
            })?;

            // Sizes (not timed): the manifest store is the anonymized file minus
            // the same file with its JUMBF removed.
            let stripped = work_dir.join("stripped.png");
            std::fs::copy(&anonymized, &stripped)?;
            c2pa::jumbf_io::remove_jumbf_from_file(&stripped).map_err(|e| anyhow!("failed to strip manifest: {e}"))?;
            let proof = NativeProof::from_base64(&proof_b64)?;
            let mut groth16 = Vec::new();
            ark_serialize::CanonicalSerialize::serialize_compressed(&proof.proof, &mut groth16)?;
            data.insert("groth16_proof_bytes".into(), json!(groth16.len()));
            data.insert("public_inputs".into(), json!(proof.public_inputs.len()));
            data.insert("proof_container_bytes".into(), json!(proof_b64.len()));
            data.insert("assertion_json_bytes".into(), json!(serde_json::to_vec(&assertion)?.len()));
            data.insert("x5chain_bytes".into(), json!(chain.iter().map(Vec::len).sum::<usize>()));
            data.insert("manifest_store_bytes".into(), json!(std::fs::metadata(&anonymized)?.len() - std::fs::metadata(&stripped)?.len()));
        }
        "verify" => {
            let proof = timed(&mut steps, "read_proof", || NativeProof::from_base64(&std::fs::read_to_string(work_dir.join("proof.b64"))?))?;
            let vk = timed(&mut steps, "load_verifying_key", || load_verifying_key(&paths.verifying_key))?;
            let pvk = timed(&mut steps, "prepare_verifying_key", || prepare_verifying_key(&vk))?;
            let valid = timed(&mut steps, "verify", || verify_proof_prepared(&proof, &pvk))?;
            if !valid {
                bail!("proof did not verify");
            }
        }
        other => bail!("unknown phase {other}"),
    }
    println!("{RESULT_PREFIX}{}", json!({ "steps": steps, "data": data }));
    Ok(())
}

// ---- Measurement ------------------------------------------------------------

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

fn phase_record(name: &str, category: &str, m: &Measured) -> Value {
    let result = m.result.clone().unwrap_or(json!({}));
    json!({
        "name": name,
        "category": category,
        "wall_s": m.wall_s,
        "peak_rss_mib": m.peak_rss_kib as f64 / 1024.0,
        "steps": result["steps"],
        "data": result["data"],
    })
}

/// Sum of wall time and maximum peak RSS over the phases named.
fn total(phases: &[Value], names: &[&str]) -> Value {
    let selected: Vec<&Value> = phases.iter().filter(|p| names.contains(&p["name"].as_str().unwrap_or(""))).collect();
    let measured = selected.iter().all(|p| p["wall_s"].is_number()) && selected.len() == names.len();
    if !measured {
        return json!({ "phases": names, "measured": false });
    }
    json!({
        "phases": names,
        "wall_s": selected.iter().map(|p| p["wall_s"].as_f64().unwrap()).sum::<f64>(),
        "peak_rss_mib": selected.iter().map(|p| p["peak_rss_mib"].as_f64().unwrap()).fold(0.0, f64::max),
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

// ---- The run ----------------------------------------------------------------

fn run(work_dir: Option<PathBuf>, circuits_dir: &Path, reuse_build: bool, keep: bool, out: Option<PathBuf>) -> Result<()> {
    let zk_root = std::env::current_dir()?;
    let exe = std::env::current_exe()?;
    let circuits_dir = std::fs::canonicalize(circuits_dir)?;

    let work_dir = create_workspace(work_dir.as_deref(), &zk_root.join("target/bench"))?;
    if let Err(e) = check_output_location(out.as_deref(), &work_dir) {
        // Only the empty directory just created is removed.
        std::fs::remove_dir(&work_dir)?;
        return Err(e);
    }
    eprintln!("Work directory: {}", work_dir.display());
    // Captured before any phase runs, so later edits to the tree are not attributed to this run.
    let environment = environment(&zk_root);
    let record = measure(&exe, &zk_root, &work_dir, &circuits_dir, reuse_build, environment)?;

    let text = serde_json::to_string_pretty(&record)?;
    match &out {
        Some(path) => std::fs::write(path, text + "\n")?,
        None => println!("{text}"),
    }
    eprintln!("\nPhase              category        wall (s)   peak RSS (MiB)");
    for p in record["phases"].as_array().unwrap() {
        let (name, category) = (p["name"].as_str().unwrap(), p["category"].as_str().unwrap());
        match (p["wall_s"].as_f64(), p["peak_rss_mib"].as_f64()) {
            (Some(w), Some(r)) => eprintln!("{name:<18} {category:<15} {w:>8.1}   {r:>14.0}"),
            _ => eprintln!("{name:<18} {category:<15} {}", p["skipped"].as_str().unwrap_or("")),
        }
    }
    eprintln!("Per-asset anonymization: {:.1} s", record["totals"]["anonymization_per_asset"]["wall_s"].as_f64().unwrap_or(f64::NAN));
    finish_workspace(&work_dir, keep)
}

fn measure(exe: &Path, zk_root: &Path, work_dir: &Path, circuits_dir: &Path, reuse_build: bool, environment: Value) -> Result<Value> {
    let build = work_dir.join("build");
    std::fs::create_dir(&build)?;
    let phase_cmd = |name: &str| {
        let mut cmd = Command::new(exe);
        cmd.args(["phase", name, "--work-dir"]).arg(work_dir).arg("--zk-root").arg(zk_root);
        cmd
    };
    let mut phases = Vec::new();
    let run_phase = |phases: &mut Vec<Value>, name: &str, category: &str, cmd: &mut Command| -> Result<()> {
        eprintln!("Phase: {name}...");
        phases.push(phase_record(name, category, &run_measured(cmd)?));
        Ok(())
    };

    run_phase(&mut phases, "fixtures", "test-fixture", &mut phase_cmd("fixtures"))?;
    if reuse_build {
        let source_build = circuits_dir.join("build");
        std::os::unix::fs::symlink(source_build.join(format!("{CIRCUIT}.r1cs")), build.join(format!("{CIRCUIT}.r1cs")))?;
        std::os::unix::fs::symlink(source_build.join(format!("{CIRCUIT}_js")), build.join(format!("{CIRCUIT}_js")))?;
        phases.push(json!({ "name": "compile", "category": "one-time", "skipped": "reused circuits/build" }));
    } else {
        run_phase(
            &mut phases,
            "compile",
            "one-time",
            Command::new("circom").arg(circuits_dir.join(format!("{CIRCUIT}.circom"))).args(["--r1cs", "--wasm", "-l"])
                .arg(circuits_dir).arg("-l").arg(circuits_dir.join("node_modules")).arg("-o").arg(&build),
        )?;
    }
    run_phase(&mut phases, "setup", "one-time", &mut phase_cmd("setup"))?;
    for name in ["prepare", "witness", "prove", "package"] {
        run_phase(&mut phases, name, "anonymization", &mut phase_cmd(name))?;
    }
    run_phase(&mut phases, "verify", "verification", &mut phase_cmd("verify"))?;
    run_phase(
        &mut phases,
        "verify_cli",
        "verification-full",
        Command::new(exe.with_file_name("c2pa-x509-zk-verify")).arg("--input").arg(work_dir.join("anon.png"))
            .arg("--trust-list").arg(work_dir.join("pki/trust-list.pem")).arg("--circuits-dir").arg(work_dir),
    )?;

    let data_of = |name: &str| phases.iter().find(|p| p["name"] == name).map(|p| p["data"].clone()).unwrap_or(Value::Null);
    let (prepare, package, setup, witness) = (data_of("prepare"), data_of("package"), data_of("setup"), data_of("witness"));
    let paths = paths(work_dir);
    let build_manifest = paths.read_build_manifest()?.ok_or_else(|| anyhow!("setup wrote no build manifest"))?;

    Ok(json!({
        "schema": "c2pa-x509-zk-bench/2",
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
        "accounting": ACCOUNTING,
        "environment": environment,
        "artifacts": {
            "r1cs_sha256": build_manifest.r1cs_sha256,
            "verifying_key_sha256": build_manifest.verifying_key_sha256,
            "r1cs_bytes": std::fs::metadata(&paths.r1cs)?.len(),
            "wasm_bytes": std::fs::metadata(&paths.wasm)?.len(),
            "proving_key_bytes": setup["proving_key_bytes"],
            "verifying_key_bytes": setup["verifying_key_bytes"],
            "constraints": witness["constraints"],
            "wires": witness["wires"],
        },
        "inputs": {
            "signer_certificate_bytes": prepare["signer_certificate_bytes"],
            "tbs_certificate_bytes": prepare["tbs_certificate_bytes"],
            "issuing_chain_certificates": prepare["issuing_chain_certificates"],
            "asset_bytes": std::fs::metadata(zk_root.join("fixtures/cards.png"))?.len(),
        },
        "totals": {
            "one_time": total(&phases, &["compile", "setup"]),
            "anonymization_per_asset": total(&phases, &["prepare", "witness", "prove", "package"]),
            "anonymization_witness_plus_prove": total(&phases, &["witness", "prove"]),
            "verification": total(&phases, &["verify"]),
            "verification_full": total(&phases, &["verify_cli"]),
        },
        "phases": phases,
        "output": {
            "groth16_proof_bytes": package["groth16_proof_bytes"],
            "public_inputs": package["public_inputs"],
            "proof_container_bytes": package["proof_container_bytes"],
            "assertion_json_bytes": package["assertion_json_bytes"],
            "x5chain_bytes": package["x5chain_bytes"],
            "manifest_store_bytes": package["manifest_store_bytes"],
            "note": "manifest_store_bytes is the whole C2PA store added to the asset, including the COSE signature's \
                     reserved padding; proof_container_bytes is the proof as embedded (base64 of JSON with the \
                     public inputs); the COSE signature field holds the same container decoded once.",
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_work_dir_is_refused_and_left_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let existing = tmp.path().join("mine");
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("notes.txt"), "keep me").unwrap();

        let err = create_workspace(Some(&existing), tmp.path()).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(std::fs::read_to_string(existing.join("notes.txt")).unwrap(), "keep me");
    }

    #[test]
    fn requested_work_dir_collision_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        assert_eq!(create_workspace(Some(&dir), tmp.path()).unwrap(), std::path::absolute(&dir).unwrap());
        assert!(create_workspace(Some(&dir), tmp.path()).is_err());
    }

    #[test]
    fn default_work_dirs_are_distinct_and_new() {
        let tmp = tempfile::tempdir().unwrap();
        let a = create_workspace(None, tmp.path()).unwrap();
        let b = create_workspace(None, tmp.path()).unwrap();
        assert_ne!(a, b);
        assert!(a.is_dir() && b.is_dir());
        assert_eq!(std::fs::read_dir(&a).unwrap().count(), 0);
    }

    #[test]
    fn output_inside_work_dir_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let work = create_workspace(Some(&tmp.path().join("run")), tmp.path()).unwrap();
        assert!(check_output_location(Some(&work.join("results.json")), &work).is_err());
        assert!(check_output_location(Some(&work.join("sub/results.json")), &work).is_err());
        assert!(check_output_location(Some(&tmp.path().join("results.json")), &work).is_ok());
        assert!(check_output_location(None, &work).is_ok());
    }

    #[test]
    fn cleanup_removes_only_the_owned_work_dir_unless_kept() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("sibling.txt"), "untouched").unwrap();

        let kept = create_workspace(None, tmp.path()).unwrap();
        std::fs::write(kept.join("witness.bin"), "data").unwrap();
        finish_workspace(&kept, true).unwrap();
        assert!(kept.join("witness.bin").exists());

        let removed = create_workspace(None, tmp.path()).unwrap();
        std::fs::write(removed.join("witness.bin"), "data").unwrap();
        finish_workspace(&removed, false).unwrap();
        assert!(!removed.exists());
        assert_eq!(std::fs::read_to_string(tmp.path().join("sibling.txt")).unwrap(), "untouched");
    }
}
