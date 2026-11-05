//! `c2pa-x509-zk-bench run --variant third-party`: the third-party statement
//! (roadmap E2b; gnark) under the same accounting as V0. Every phase is a
//! separate process; steps inside the gnark CLI's phases come from the
//! timings it prints.
//!
//! | Phase       | Category          | Work                                                              |
//! |-------------|-------------------|-------------------------------------------------------------------|
//! | fixtures    | test-fixture      | mirror PKI, sign the sample asset with the local TSA              |
//! | setup       | one-time          | `c2pa-zk-gnark setup`: compile the circuit, Groth16 setup         |
//! | prepare     | anonymization     | read the manifest, check the claim (Q9), validate the chain, build inputs, check the size |
//! | prove       | anonymization     | `c2pa-zk-gnark prove`, cold: its files evicted from the page cache |
//! | self_verify | anonymization     | `c2pa-zk-gnark verify`: the anonymizer checks its own proof       |
//! | package     | anonymization     | encode the ZK signature, replace the original in place            |
//! | verify      | verification      | `c2pa-zk-gnark verify`                                            |
//! | verify_cli  | verification-full | the verifier CLI on the anonymized asset (time stamp, chain, c2pa checks, proof) |
//! | prove_warm  | supplementary     | `c2pa-zk-gnark prove` again, its files in the page cache; not in any total |
//!
//! prove and prove_warm each run three times (this laptop's timings vary
//! widely); the median run is reported, with every run in the record.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};

use c2pa_x509_zk_demo::jumbf::{active_manifest, manifest_store};
use c2pa_x509_zk_demo::original_signature::OriginalSignature;
use c2pa_x509_zk_demo::third_party::{check_claim, replace_signature, statement_inputs};
use c2pa_x509_zk_demo::zk_signature::{ZkSignature, PROOF_LEN};
use c2pa_x509_zk_demo::{issuing_path_for, file_sha256, TrustList};

use super::pk_load::{cache_state, evict, resident_fraction};
use super::{phase_record, run_measured, timed, total, Measured, RESULT_PREFIX};

const STATEMENT: &str = "Third-party anonymization, trust model A (THIRD-PARTY-STATEMENT.md): the issuing CA's \
P-384 key (a public input) signed, with ECDSA-SHA384, a certificate whose DER structure shows a P-256 subject key, \
validity containing t, exactly one extended key usage including C2PA claim signing, and not a CA; that certificate \
is the first x5chain entry of the original protected header, and its key signed (ES256) the Sig_structure of the \
public claim; and the public sigTst2 imprint is the SHA-256 of the countersignature over that signature. \
Off-circuit: the time-stamp token against the TSA trust list at its time t, the issuing chain against the trust \
list at t, and the claim's assertions and hard binding with c2pa.";

const ACCOUNTING: &str = "As V0: one_time = setup (here one process compiling the circuit and running the Groth16 \
setup). anonymization_per_asset = prepare + prove + self_verify + package: the complete latency from a signed \
asset to an anonymized one; prove is measured cold (the constraint system and proving key evicted from the Linux \
page cache before it, the observed residency recorded) and includes loading both files, solving the witness, and \
proving, as separate steps; anonymization_witness_plus_prove = prove. verification = the gnark verify process \
(loading the verifying key and verifying); verification_full = the verifier CLI on the anonymized asset. prove_warm \
repeats prove with its files resident and is in no total. Each of prove and prove_warm is run three times; \
the phase reports the median run by wall time (its steps) and the maximum peak memory, with every run and its \
observed cache state in data.runs. test_fixture is in no total. Peak memory per category is \
the maximum over its phases, each a separate process.";

/// One phase run inside a subprocess (the Rust-side phases).
pub fn phase(name: &str, work_dir: &Path, zk_root: &Path) -> Result<()> {
    let pki = work_dir.join("pki");
    let signed = work_dir.join("signed.png");
    let mut steps = serde_json::Map::new();
    let mut data = serde_json::Map::new();
    match name {
        "tp-fixtures" => {
            timed(&mut steps, "generate_pki", || {
                let ok = Command::new("bash").arg(zk_root.join("generate-test-pki.sh")).arg("--mirror").arg(&pki).arg("Bench")
                    .stdout(Stdio::null()).stderr(Stdio::null()).status()?.success();
                if !ok { bail!("generate-test-pki.sh --mirror failed") }
                Ok(())
            })?;
            timed(&mut steps, "sign_asset", || {
                let sign = std::env::current_exe()?.with_file_name("c2pa-x509-zk-sign");
                let mut cmd = Command::new(sign);
                cmd.arg("--input").arg(zk_root.join("fixtures/cards.png")).arg("--output").arg(&signed);
                for (flag, file) in [("--cert", "signer.pem"), ("--key", "signer.key"), ("--ca", "issuing-ca.pem"), ("--tsa-cert", "tsa.pem"), ("--tsa-key", "tsa.key")] {
                    cmd.arg(flag).arg(pki.join(file));
                }
                if !cmd.stdout(Stdio::null()).status()?.success() { bail!("signing failed") }
                Ok(())
            })?;
        }
        "tp-prepare" => {
            let trust = timed(&mut steps, "load_trust_list", || TrustList::from_file(&pki.join("trust-list.pem")))?;
            let (store, manifest) = timed(&mut steps, "read_manifest", || {
                let store = manifest_store(&signed)?;
                let manifest = active_manifest(&store)?;
                Ok((store, manifest))
            })?;
            timed(&mut steps, "check_claim", || check_claim(&store, &manifest.claim))?;
            // Parses the original signature, checks the time stamp's imprint, and
            // validates the signer's issuing path at its time.
            let inputs = timed(&mut steps, "build_inputs", || statement_inputs(&signed, &trust))?;
            let original = OriginalSignature::from_manifest(manifest.clone())?;
            let chain = issuing_path_for(original.signer_certificate()?, &original.x5chain[1..], &trust, inputs.public.time)?;
            let keys = work_dir.join("keys");
            let vk_sha256 = keys_manifest(&keys)?["sha256"]["statement.vk"].as_str().unwrap_or_default().to_string();
            let token = original.time_stamp.as_ref().ok_or_else(|| anyhow!("no time stamp"))?.token.clone();
            let size = manifest.cose_sign1.len();
            let spare = timed(&mut steps, "check_size", || {
                let signature = ZkSignature { issuing_chain: chain.clone(), vk_sha256: vk_sha256.clone(), time_stamp_token: token.clone(), proof: vec![0; PROOF_LEN] };
                signature.encode_exact(size)?;
                Ok(size - signature.encode(0, 0).len())
            })?;
            timed(&mut steps, "write_inputs", || {
                std::fs::write(work_dir.join("inputs.json"), serde_json::to_vec(&inputs)?)?;
                std::fs::write(work_dir.join("public.json"), serde_json::to_vec(&inputs.public)?)?;
                let context = json!({ "issuing_chain": chain.iter().map(|c| super::b64(c)).collect::<Vec<_>>(), "vk_sha256": vk_sha256, "token": super::b64(&token) });
                Ok(std::fs::write(work_dir.join("context.json"), serde_json::to_vec(&context)?)?)
            })?;
            let tbs_len = original.signer_certificate()?.get(6..8).map(|b| 4 + (b[0] as usize) * 256 + b[1] as usize).unwrap_or(0);
            data.insert("claim_bytes".into(), json!(original.manifest.claim.len()));
            data.insert("protected_header_bytes".into(), json!(original.protected.len()));
            data.insert("signer_certificate_bytes".into(), json!(original.signer_certificate()?.len()));
            data.insert("tbs_certificate_bytes".into(), json!(tbs_len));
            data.insert("issuing_chain_certificates".into(), json!(chain.len()));
            data.insert("claim_signature_bytes".into(), json!(size));
            data.insert("spare_bytes".into(), json!(spare));
        }
        "tp-package" => {
            let context: Value = timed(&mut steps, "read_context", || Ok(serde_json::from_slice(&std::fs::read(work_dir.join("context.json"))?)?))?;
            let decode = |v: &Value| -> Result<Vec<u8>> { Ok(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v.as_str().unwrap_or_default())?) };
            let proof = std::fs::read(work_dir.join("proof.bin"))?;
            let (store, manifest) = timed(&mut steps, "read_manifest", || {
                let store = manifest_store(&signed)?;
                let manifest = active_manifest(&store)?;
                Ok((store, manifest))
            })?;
            let cose = timed(&mut steps, "encode_signature", || {
                let signature = ZkSignature {
                    issuing_chain: context["issuing_chain"].as_array().ok_or_else(|| anyhow!("no chain"))?.iter().map(decode).collect::<Result<_>>()?,
                    vk_sha256: context["vk_sha256"].as_str().unwrap_or_default().to_string(),
                    time_stamp_token: decode(&context["token"])?,
                    proof: proof.clone(),
                };
                signature.encode_exact(manifest.cose_sign1.len())
            })?;
            let anonymized = work_dir.join("anon.png");
            timed(&mut steps, "replace_signature", || replace_signature(&signed, &anonymized, &store, &manifest, &cose))?;
            data.insert("proof_bytes".into(), json!(proof.len()));
            data.insert("zk_signature_bytes".into(), json!(cose.len()));
            data.insert("x5chain_bytes".into(), json!(context["issuing_chain"].as_array().map(|c| c.iter().map(|v| decode(v).map(|d| d.len()).unwrap_or(0)).sum::<usize>())));
            data.insert("manifest_store_bytes".into(), json!(store.len()));
            data.insert("asset_bytes_signed".into(), json!(std::fs::metadata(&signed)?.len()));
            data.insert("asset_bytes_anonymized".into(), json!(std::fs::metadata(&anonymized)?.len()));
        }
        other => bail!("unknown third-party phase {other}"),
    }
    println!("{RESULT_PREFIX}{}", json!({ "steps": steps, "data": data }));
    Ok(())
}

fn keys_manifest(keys: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&std::fs::read(keys.join("keys.json"))?)?)
}

/// Steps from the gnark CLI's stderr: its "<step>: <seconds> s" lines, and the
/// solver's time from gnark's own log ("constraint system solver done ... took=<ms>").
fn gnark_steps(stderr: &str) -> serde_json::Map<String, Value> {
    let mut steps = serde_json::Map::new();
    for line in stderr.lines() {
        let plain = strip_ansi(line);
        if let Some((name, rest)) = plain.split_once(": ") {
            if let Some(seconds) = rest.strip_suffix(" s").and_then(|v| v.trim().parse::<f64>().ok()) {
                if !name.contains(' ') || name.starts_with("load ") {
                    steps.insert(format!("{}_s", name.replace(' ', "_")), json!(seconds));
                }
            }
        }
        if plain.contains("constraint system solver done") {
            if let Some(ms) = plain.split("took=").nth(1).and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse::<f64>().ok()) {
                steps.insert("solve_s".into(), json!(ms / 1000.0));
            }
        }
    }
    steps
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A gnark CLI phase: measured, with its steps parsed from its output (the
/// CLI prints its timings to stderr; gnark's logger writes to stdout).
fn gnark_phase(name: &str, category: &str, cmd: &mut Command) -> Result<Value> {
    eprintln!("Phase: {name}...");
    let m: Measured = run_measured(cmd)?;
    let mut record = phase_record(name, category, &m);
    record["steps"] = Value::Object(gnark_steps(&format!("{}\n{}", m.stderr, m.stdout)));
    Ok(record)
}

const PROVER_FILES: [&str; 2] = ["statement.ccs", "statement.pk"];

/// The prover files' residency in the page cache, after evicting them if
/// `evict_first`. Files just written by setup have dirty pages, which cannot
/// be evicted until written back, so each is synced first.
fn prover_files_residency(keys: &Path, evict_first: bool) -> Result<Value> {
    let mut residency = serde_json::Map::new();
    for file in PROVER_FILES {
        let path = keys.join(file);
        if evict_first {
            std::fs::File::open(&path)?.sync_all()?;
            evict(&path)?;
        }
        residency.insert(file.into(), json!(resident_fraction(&path)?));
    }
    Ok(Value::Object(residency))
}

/// `reps` prove runs, cold (files evicted first) or warm, each in its own
/// process. The phase reports the median run (by wall time) with its steps,
/// the maximum peak memory, and every run with its observed cache state.
fn prove_runs(name: &str, category: &str, cold: bool, reps: usize, keys: &Path, cmd: impl Fn() -> Command) -> Result<Value> {
    let mut runs = Vec::new();
    for rep in 0..reps {
        let residency = prover_files_residency(keys, cold)?;
        let mut run = gnark_phase(&format!("{name} ({}/{reps})", rep + 1), category, &mut cmd())?;
        run["cache"] = json!(cache_label(cold, &residency));
        run["resident_before"] = residency;
        runs.push(run);
    }
    let mut by_wall: Vec<&Value> = runs.iter().collect();
    by_wall.sort_by(|a, b| a["wall_s"].as_f64().partial_cmp(&b["wall_s"].as_f64()).unwrap());
    let median = by_wall[by_wall.len() / 2];
    let caches: Vec<&str> = runs.iter().filter_map(|r| r["cache"].as_str()).collect();
    Ok(json!({
        "name": name,
        "category": category,
        "wall_s": median["wall_s"],
        "peak_rss_mib": runs.iter().filter_map(|r| r["peak_rss_mib"].as_f64()).fold(0.0, f64::max),
        "steps": median["steps"],
        "data": {
            "statistic": format!("median of {reps} runs (wall time); peak memory is the maximum"),
            "cache": if caches.iter().all(|c| *c == caches[0]) { caches[0] } else { "mixed" },
            "runs": runs,
        },
    }))
}

fn cache_label(evicted: bool, residency: &Value) -> &'static str {
    let worst = residency.as_object().map(|m| m.values().filter_map(Value::as_f64).fold(0.0, f64::max)).unwrap_or(1.0);
    cache_state(evicted, worst).label()
}

/// Prove runs per cache state; the per-asset figure is the cold median.
pub const PROVE_REPS: usize = 3;

pub fn measure(exe: &Path, zk_root: &Path, work_dir: &Path, gnark: &Path, environment: Value) -> Result<Value> {
    let reps = PROVE_REPS;
    let keys = work_dir.join("keys");
    let phase_cmd = |name: &str| {
        let mut cmd = Command::new(exe);
        cmd.args(["phase", name, "--work-dir"]).arg(work_dir).arg("--zk-root").arg(zk_root);
        cmd
    };
    let gnark_cmd = |args: &[&std::ffi::OsStr]| {
        let mut cmd = Command::new(gnark);
        cmd.args(args);
        cmd
    };
    let mut phases = Vec::new();
    let run_phase = |phases: &mut Vec<Value>, name: &str, category: &str, cmd: &mut Command| -> Result<()> {
        eprintln!("Phase: {name}...");
        phases.push(phase_record(name, category, &run_measured(cmd)?));
        Ok(())
    };
    let (inputs, public, proof) = (work_dir.join("inputs.json"), work_dir.join("public.json"), work_dir.join("proof.bin"));
    let prove_args = ["prove".as_ref(), "--keys".as_ref(), keys.as_os_str(), "--input".as_ref(), inputs.as_os_str(), "--proof".as_ref(), proof.as_os_str()];
    let verify_args = ["verify".as_ref(), "--keys".as_ref(), keys.as_os_str(), "--public".as_ref(), public.as_os_str(), "--proof".as_ref(), proof.as_os_str()];

    run_phase(&mut phases, "fixtures", "test-fixture", &mut phase_cmd("tp-fixtures"))?;
    phases.push(gnark_phase("setup", "one-time", &mut gnark_cmd(&["setup".as_ref(), "--keys".as_ref(), keys.as_os_str()]))?);
    run_phase(&mut phases, "prepare", "anonymization", &mut phase_cmd("tp-prepare"))?;

    phases.push(prove_runs("prove", "anonymization", true, reps, &keys, || gnark_cmd(&prove_args))?);
    phases.push(gnark_phase("self_verify", "anonymization", &mut gnark_cmd(&verify_args))?);
    run_phase(&mut phases, "package", "anonymization", &mut phase_cmd("tp-package"))?;
    phases.push(gnark_phase("verify", "verification", &mut gnark_cmd(&verify_args))?);
    run_phase(
        &mut phases,
        "verify_cli",
        "verification-full",
        Command::new(exe.with_file_name("c2pa-x509-zk-verify"))
            .arg("--input").arg(work_dir.join("anon.png"))
            .arg("--trust-list").arg(work_dir.join("pki/trust-list.pem"))
            .arg("--tsa-trust-list").arg(work_dir.join("pki/tsa-trust-list.pem"))
            .arg("--keys").arg(&keys).arg("--gnark").arg(gnark),
    )?;
    // Warm runs: read the files once so they are resident, then prove.
    for file in PROVER_FILES {
        std::io::copy(&mut std::fs::File::open(keys.join(file))?, &mut std::io::sink())?;
    }
    phases.push(prove_runs("prove_warm", "supplementary", false, reps, &keys, || gnark_cmd(&prove_args))?);

    let data_of = |name: &str| phases.iter().find(|p| p["name"] == name).map(|p| p["data"].clone()).unwrap_or(Value::Null);
    let (prepare, package) = (data_of("prepare"), data_of("package"));
    let manifest = keys_manifest(&keys)?;
    let size = |f: &str| std::fs::metadata(keys.join(f)).map(|m| m.len()).unwrap_or(0);

    Ok(json!({
        "schema": "c2pa-x509-zk-bench/2",
        "variant": {
            "mode": "third-party",
            "trust_model": "A",
            "signer_key": "P-256 (ES256 claim signature)",
            "ca_signature": "ECDSA P-384 with SHA-384",
            "time_stamp": "sigTst2, imprint bound in the circuit, token verified off-circuit",
            "proof_system": "Groth16 (gnark v0.16.4, native Go witness solving, one BSB22 commitment)",
            "curve": "BN254",
            "circuit": "gnark/statement (third-party/1)",
        },
        "statement": STATEMENT,
        "accounting": ACCOUNTING,
        "environment": environment,
        "artifacts": {
            "constraints": manifest["constraints"],
            "sizes": manifest["sizes"],
            "verifying_key_sha256": manifest["sha256"]["statement.vk"],
            "constraint_system_bytes": size("statement.ccs"),
            "proving_key_bytes": size("statement.pk"),
            "verifying_key_bytes": size("statement.vk"),
            "gnark_cli_sha256": file_sha256(gnark)?,
        },
        "inputs": {
            "claim_bytes": prepare["claim_bytes"],
            "protected_header_bytes": prepare["protected_header_bytes"],
            "signer_certificate_bytes": prepare["signer_certificate_bytes"],
            "tbs_certificate_bytes": prepare["tbs_certificate_bytes"],
            "issuing_chain_certificates": prepare["issuing_chain_certificates"],
            "asset_bytes": std::fs::metadata(zk_root.join("fixtures/cards.png"))?.len(),
        },
        "totals": {
            "one_time": total(&phases, &["setup"]),
            "anonymization_per_asset": total(&phases, &["prepare", "prove", "self_verify", "package"]),
            "anonymization_witness_plus_prove": total(&phases, &["prove"]),
            "verification": total(&phases, &["verify"]),
            "verification_full": total(&phases, &["verify_cli"]),
        },
        "phases": phases,
        "output": {
            "proof_bytes": package["proof_bytes"],
            "public_inputs": 50,
            "zk_signature_bytes": package["zk_signature_bytes"],
            "claim_signature_bytes_original": prepare["claim_signature_bytes"],
            "spare_bytes": prepare["spare_bytes"],
            "x5chain_bytes": package["x5chain_bytes"],
            "manifest_store_bytes": package["manifest_store_bytes"],
            "asset_bytes_signed": package["asset_bytes_signed"],
            "asset_bytes_anonymized": package["asset_bytes_anonymized"],
            "note": "The ZK signature replaces the original claim signature in place at the same size, so the manifest \
                     store and the asset keep their sizes; spare_bytes is the padding left. The proof is embedded \
                     as raw bytes; its public inputs are derived by the verifier.",
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_gnark_cli_timings() {
        let stderr = "load constraint system: 1.27 s\nload proving key: 60.71 s\n\
                      \u{1b}[90m15:44:08\u{1b}[0m DBG constraint system solver done \u{1b}[36mnbConstraints=\u{1b}[0m4710762 \u{1b}[36mtook=\u{1b}[0m2056.566974\n\
                      prove: 18.49 s\nerror: something: 3 s\n";
        let steps = gnark_steps(stderr);
        assert_eq!(steps["load_constraint_system_s"], json!(1.27));
        assert_eq!(steps["load_proving_key_s"], json!(60.71));
        assert_eq!(steps["prove_s"], json!(18.49));
        assert_eq!(steps["solve_s"], json!(2.056566974));
        assert!(!steps.contains_key("error_s") && steps.len() == 4, "{steps:?}");
    }
}
