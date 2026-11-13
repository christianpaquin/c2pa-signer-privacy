//! `c2pa-x509-zk-bench run --variant third-party`: the third-party statement
//! (roadmap E2b; gnark) under the same accounting as M0. Every phase is a
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
//!
//! With --hide-issuer (roadmap H4), the hidden-issuer statement: prepare also
//! builds the issuer tree over the trust list's eligible issuers (the
//! anonymizer does so for each asset), prove takes them, package writes the
//! hidden form of the ZK signature, and verify_cli applies an issuer policy
//! approving the trust list. With --hide-time-stamp too (roadmap I6), the
//! statement hiding the issuer and the time stamp: prepare also builds the TSA
//! tree, the window is the time stamp's UTC day, and the policy approves the
//! TSA trust list as a TSA snapshot.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use c2pa_x509_zk_demo::jumbf::{active_manifest, manifest_store};
use c2pa_x509_zk_demo::original_signature::OriginalSignature;
use c2pa_x509_zk_demo::third_party::{check_claim, purpose_tree, replace_signature, statement_inputs, HiddenAllPublicInputs, HiddenPublicInputs, Prover, VARIANT_HIDDEN_ALL, VARIANT_HIDDEN_ISSUER};
use c2pa_x509_zk_demo::zk_signature::{proof_len, IssuerTreeRef, ZkSignature, DEFAULT_CURVE};
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

const STATEMENT_HIDDEN_ISSUER: &str = "Third-party anonymization, hidden issuer (roadmap H4; HIDING-THE-ISSUER.md): \
as the disclosed statement, except that the issuing CA's P-384 key is private, and a member of the issuer tree \
(Poseidon2, leaf tag 1) whose root is a public input, its certificate valid at t; the public sigTst2 imprint is \
the SHA-256 of the countersignature over the original signature. Off-circuit: the time-stamp token against the TSA \
trust list at its time t, the root against the verifier's issuer policy (approved trust-list snapshots), and the \
claim's assertions and hard binding with c2pa.";

const STATEMENT_HIDDEN_ALL: &str = "Third-party anonymization, hidden issuer and time stamp (roadmap I6; \
HIDING-THE-TIME-STAMP.md): as the hidden-issuer statement, with the time-stamp token verified in the circuit under \
a reduced profile: the TSA's ES256 signature over the signed attributes, TSTInfo and its imprint of the original \
signature, the TSA certificate signed (ECDSA-SHA384) by a TSA CA that is a member of the TSA tree (leaf tag 4) \
whose root is a public input, and genTime in the public half-open window [t1, t2); the exact time, the imprint, \
and the token are private. Off-circuit: both roots against the verifier's policy (issuer and TSA snapshots, each \
containing the window), and the claim's assertions and hard binding with c2pa.";

/// The statement's public inputs, as the verifier supplies them (gnark adds one
/// internal input for its BSB22 commitment): the claim packed 31 bytes per
/// element and its length, then the disclosed statement's issuing CA key (P-384,
/// 12 limbs), time, and imprint (2); the hidden issuer's root, time, and imprint;
/// or the hidden-all statement's two roots and window. See gnark/statement.
fn public_inputs(statement: &str, max_claim: u64) -> u64 {
    let claim = max_claim.div_ceil(31) + 1;
    match statement {
        VARIANT_HIDDEN_ISSUER => claim + 1 + 1 + 2,
        VARIANT_HIDDEN_ALL => claim + 2 + 2,
        _ => claim + 12 + 1 + 2,
    }
}

const ACCOUNTING: &str = "As M0: one_time = setup (here one process compiling the circuit and running the Groth16 \
setup). anonymization_per_asset = prepare + prove + self_verify + package: the complete latency from a signed \
asset to an anonymized one; prove is measured cold (the constraint system and proving key evicted from the Linux \
page cache before it, the observed residency recorded) and includes loading both files, solving the witness, and \
proving, as separate steps; anonymization_witness_plus_prove = prove. verification = the gnark verify process \
(loading the verifying key and verifying); verification_full = the verifier CLI on the anonymized asset. prove_warm \
repeats prove with its files resident and is in no total. Each of prove and prove_warm is run three times; \
the phase reports the median run by wall time (its steps) and the maximum peak memory, with every run and its \
observed cache state in data.runs. The per-asset total's prove_cache is the prove phase's observed state: \
the figure is a cold measurement only when it is cold (eviction-failed or mixed otherwise). test_fixture is in no total. Peak memory per category is \
the maximum over its phases, each a separate process.";

/// Where a run's inputs and outputs are: the generated fixture by default, or
/// an external signed asset with given trust lists (roadmap R2). Written to
/// the work directory so the phase subprocesses read the same paths.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Paths {
    pub signed: PathBuf,
    pub anonymized: PathBuf,
    pub trust_list: PathBuf,
    pub tsa_trust_list: PathBuf,
    pub keys: PathBuf,
}

/// An external signed asset and the trust lists to anonymize and verify it against.
#[derive(Debug, Clone)]
pub struct External {
    pub asset: PathBuf,
    pub trust_list: PathBuf,
    pub tsa_trust_list: PathBuf,
}

impl Paths {
    fn new(work_dir: &Path, external: Option<&External>, keys: Option<&Path>) -> Result<Self> {
        let keys = keys.map(Path::to_path_buf).unwrap_or_else(|| work_dir.join("keys"));
        Ok(match external {
            None => Paths {
                signed: work_dir.join("signed.png"),
                anonymized: work_dir.join("anon.png"),
                trust_list: work_dir.join("pki/trust-list.pem"),
                tsa_trust_list: work_dir.join("pki/tsa-trust-list.pem"),
                keys,
            },
            Some(e) => {
                let ext = e.asset.extension().and_then(|x| x.to_str()).ok_or_else(|| anyhow!("{} has no file extension", e.asset.display()))?;
                Paths {
                    signed: std::fs::canonicalize(&e.asset)?,
                    anonymized: work_dir.join(format!("anon.{ext}")),
                    trust_list: std::fs::canonicalize(&e.trust_list)?,
                    tsa_trust_list: std::fs::canonicalize(&e.tsa_trust_list)?,
                    keys,
                }
            }
        })
    }

    fn file(work_dir: &Path) -> PathBuf {
        work_dir.join("tp-paths.json")
    }

    fn load(work_dir: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(Self::file(work_dir))?)?)
    }
}

/// A file's name and SHA-256, for the record.
fn identify(path: &Path) -> Result<Value> {
    Ok(json!({ "name": path.file_name().and_then(|n| n.to_str()).unwrap_or_default(), "sha256": file_sha256(path)?, "bytes": std::fs::metadata(path)?.len() }))
}

/// One phase run inside a subprocess (the Rust-side phases).
pub fn phase(name: &str, work_dir: &Path, zk_root: &Path) -> Result<()> {
    let paths = Paths::load(work_dir)?;
    let pki = work_dir.join("pki");
    let signed = paths.signed.clone();
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
            let trust = timed(&mut steps, "load_trust_list", || TrustList::from_file(&paths.trust_list))?;
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
            let keys = keys_manifest(&paths.keys)?;
            let vk_sha256 = keys["sha256"]["statement.vk"].as_str().unwrap_or_default().to_string();
            let curve = keys["curve"].as_str().unwrap_or(DEFAULT_CURVE).to_string();
            let token = original.time_stamp.as_ref().ok_or_else(|| anyhow!("no time stamp"))?.token.clone();
            // The hidden issuer (H4): the tree over the eligible issuers, as
            // the anonymizer builds it for each asset.
            let hidden_all = keys["variant"].as_str() == Some(VARIANT_HIDDEN_ALL);
            let issuers = if hidden_all || keys["variant"].as_str() == Some(VARIANT_HIDDEN_ISSUER) {
                let tree = timed(&mut steps, "build_issuer_tree", || {
                    if !trust.is_anchor(&chain[0]) {
                        bail!("the issuing CA is not itself on the trust list (HIDING-THE-ISSUER.md, I2)");
                    }
                    let gnark = PathBuf::from(std::env::var_os("C2PA_ZK_GNARK").ok_or_else(|| anyhow!("C2PA_ZK_GNARK not set"))?);
                    let prover = Prover { cli: gnark, keys: paths.keys.clone() };
                    Ok(purpose_tree(&trust, c2pa_x509_zk_demo::trust::Purpose::ClaimSigning, &prover, work_dir)?.0)
                })?;
                data.insert("issuer_tree_entries".into(), json!(tree.entries));
                std::fs::write(
                    work_dir.join("policy.json"),
                    serde_json::to_vec(&json!({
                        "snapshots": [{ "name": "bench-list", "trust_list": paths.trust_list, "from": 0 }],
                        "tsa_snapshots": [{ "name": "bench-tsa", "trust_list": paths.tsa_trust_list, "from": 0 }],
                    }))?,
                )?;
                Some(IssuerTreeRef { root: tree.root, list: "bench-list".into() })
            } else {
                None
            };
            // The hidden time stamp (I6): the TSA tree, as the anonymizer
            // builds it for each asset, and the UTC day's window.
            let (tsa, window) = if hidden_all {
                let tree = timed(&mut steps, "build_tsa_tree", || {
                    let gnark = PathBuf::from(std::env::var_os("C2PA_ZK_GNARK").ok_or_else(|| anyhow!("C2PA_ZK_GNARK not set"))?);
                    let prover = Prover { cli: gnark, keys: paths.keys.clone() };
                    let tsa_trust = TrustList::from_file(&paths.tsa_trust_list)?;
                    Ok(purpose_tree(&tsa_trust, c2pa_x509_zk_demo::trust::Purpose::TimeStamping, &prover, work_dir)?.0)
                })?;
                data.insert("tsa_tree_entries".into(), json!(tree.entries));
                let t = inputs.public.time;
                (Some(IssuerTreeRef { root: tree.root, list: "bench-tsa".into() }), Some((t - t % 86_400, t - t % 86_400 + 86_400)))
            } else {
                (None, None)
            };
            let token = if tsa.is_some() { Vec::new() } else { token };
            let disclosed_chain = if issuers.is_some() { Vec::new() } else { chain.clone() };
            let size = manifest.cose_sign1.len();
            let spare = timed(&mut steps, "check_size", || {
                let signature = ZkSignature { issuing_chain: disclosed_chain.clone(), issuers: issuers.clone(), tsa: tsa.clone(), window, vk_sha256: vk_sha256.clone(), curve: curve.clone(), time_stamp_token: token.clone(), proof: vec![0; proof_len(&curve)?] };
                signature.encode_exact(size)?;
                Ok(size - signature.encode(0, 0).len())
            })?;
            timed(&mut steps, "write_inputs", || {
                std::fs::write(work_dir.join("inputs.json"), serde_json::to_vec(&inputs)?)?;
                let public = match (&issuers, &tsa, window) {
                    (None, _, _) => serde_json::to_vec(&inputs.public)?,
                    (Some(tree), Some(tsa), Some((t1, t2))) => serde_json::to_vec(&HiddenAllPublicInputs { claim: inputs.public.claim.clone(), issuer_root: tree.root.clone(), tsa_root: tsa.root.clone(), t1, t2 })?,
                    (Some(tree), _, _) => serde_json::to_vec(&HiddenPublicInputs { claim: inputs.public.claim.clone(), issuer_root: tree.root.clone(), time: inputs.public.time, imprint: inputs.public.imprint.clone() })?,
                };
                std::fs::write(work_dir.join("public.json"), public)?;
                let context = json!({
                    "issuing_chain": disclosed_chain.iter().map(|c| super::b64(c)).collect::<Vec<_>>(),
                    "issuers": issuers.as_ref().map(|t| json!({ "root": t.root, "list": t.list })),
                    "tsa": tsa.as_ref().map(|t| json!({ "root": t.root, "list": t.list })),
                    "window": window.map(|(t1, t2)| json!([t1, t2])),
                    "vk_sha256": vk_sha256, "curve": curve, "token": super::b64(&token),
                });
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
                    issuers: context["issuers"].as_object().map(|t| IssuerTreeRef {
                        root: t["root"].as_str().unwrap_or_default().to_string(),
                        list: t["list"].as_str().unwrap_or_default().to_string(),
                    }),
                    tsa: context["tsa"].as_object().map(|t| IssuerTreeRef {
                        root: t["root"].as_str().unwrap_or_default().to_string(),
                        list: t["list"].as_str().unwrap_or_default().to_string(),
                    }),
                    window: context["window"].as_array().map(|w| (w[0].as_u64().unwrap_or_default(), w[1].as_u64().unwrap_or_default())),
                    vk_sha256: context["vk_sha256"].as_str().unwrap_or_default().to_string(),
                    curve: context["curve"].as_str().unwrap_or(DEFAULT_CURVE).to_string(),
                    time_stamp_token: decode(&context["token"])?,
                    proof: proof.clone(),
                };
                signature.encode_exact(manifest.cose_sign1.len())
            })?;
            let anonymized = paths.anonymized.clone();
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
                if name.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_') {
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

/// How the prover stores and loads its proving key (roadmap E6): the file
/// format (compressed, raw, or dump; `c2pa-zk-gnark convert-pk` writes the
/// last two) and whether points are validated on load (full or none).
#[derive(Debug, Clone, Copy)]
pub struct KeyLoading {
    pub format: &'static str,
    pub check: &'static str,
}

impl KeyLoading {
    pub fn parse(format: &str, check: &str) -> Result<Self> {
        let format = ["compressed", "raw", "dump"].into_iter().find(|f| *f == format).ok_or_else(|| anyhow!("unknown key format {format}"))?;
        let check = ["full", "none"].into_iter().find(|c| *c == check).ok_or_else(|| anyhow!("unknown key check {check}"))?;
        if format == "dump" && check == "full" {
            bail!("a dumped proving key cannot be validated on load");
        }
        Ok(KeyLoading { format, check })
    }

    fn proving_key_file(self) -> &'static str {
        match self.format {
            "raw" => "statement.pk.raw",
            "dump" => "statement.pk.dump",
            _ => "statement.pk",
        }
    }

    /// The files the prover reads: the constraint system and the proving key.
    fn prover_files(self) -> [&'static str; 2] {
        ["statement.ccs", self.proving_key_file()]
    }
}

/// The prover files' residency in the page cache, after evicting them if
/// `evict_first`. Files just written by setup have dirty pages, which cannot
/// be evicted until written back, so each is synced first.
fn prover_files_residency(keys: &Path, files: [&str; 2], evict_first: bool) -> Result<Value> {
    let mut residency = serde_json::Map::new();
    for file in files {
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
fn prove_runs(name: &str, category: &str, cold: bool, reps: usize, keys: &Path, files: [&str; 2], cmd: impl Fn() -> Command) -> Result<Value> {
    let mut runs = Vec::new();
    for rep in 0..reps {
        let residency = prover_files_residency(keys, files, cold)?;
        let mut run = gnark_phase(&format!("{name} ({}/{reps})", rep + 1), category, &mut cmd())?;
        run["cache"] = json!(cache_label(cold, &residency));
        run["resident_before"] = residency;
        runs.push(run);
    }
    Ok(aggregate_runs(name, category, runs))
}

/// One phase from repeated runs: the median run by wall time (its steps
/// kept together, not medians of each step), the maximum peak memory, every
/// run, and the observed cache state: the runs' common label, or "mixed".
fn aggregate_runs(name: &str, category: &str, runs: Vec<Value>) -> Value {
    let mut by_wall: Vec<&Value> = runs.iter().collect();
    by_wall.sort_by(|a, b| a["wall_s"].as_f64().partial_cmp(&b["wall_s"].as_f64()).unwrap());
    let median = by_wall[by_wall.len() / 2];
    let caches: Vec<&str> = runs.iter().map(|r| r["cache"].as_str().unwrap_or("unknown")).collect();
    let cache = if caches.iter().all(|c| *c == caches[0]) { caches[0] } else { "mixed" };
    json!({
        "name": name,
        "category": category,
        "wall_s": median["wall_s"],
        "peak_rss_mib": runs.iter().filter_map(|r| r["peak_rss_mib"].as_f64()).fold(0.0, f64::max),
        "steps": median["steps"],
        "data": {
            "statistic": format!("median of {} runs (wall time); peak memory is the maximum", runs.len()),
            "cache": cache,
            "runs": runs,
        },
    })
}

fn cache_label(evicted: bool, residency: &Value) -> &'static str {
    let worst = residency.as_object().map(|m| m.values().filter_map(Value::as_f64).fold(0.0, f64::max)).unwrap_or(1.0);
    cache_state(evicted, worst).label()
}

/// Prove runs per cache state; the per-asset figure is the cold median.
pub const PROVE_REPS: usize = 3;

/// Measure the third-party variant: on the generated fixture, or on an
/// external asset (`external`); with existing keys (`keys`, setup not
/// measured) or new ones.
pub fn measure(
    exe: &Path,
    zk_root: &Path,
    work_dir: &Path,
    gnark: &Path,
    environment: Value,
    external: Option<&External>,
    keys: Option<&Path>,
    key_loading: KeyLoading,
    curve: &str,
    hide_issuer: bool,
    hide_time_stamp: bool,
) -> Result<Value> {
    let files = key_loading.prover_files();
    let reps = PROVE_REPS;
    let paths = Paths::new(work_dir, external, keys)?;
    std::fs::write(Paths::file(work_dir), serde_json::to_vec_pretty(&paths)?)?;
    let keys = paths.keys.clone();
    let phase_cmd = |name: &str| {
        let mut cmd = Command::new(exe);
        cmd.args(["phase", name, "--work-dir"]).arg(work_dir).arg("--zk-root").arg(zk_root).env("C2PA_ZK_GNARK", gnark);
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
    let issuers_pem = work_dir.join(c2pa_x509_zk_demo::third_party::eligible_issuers_file(c2pa_x509_zk_demo::trust::Purpose::ClaimSigning));
    let mut prove_args: Vec<&std::ffi::OsStr> = vec![
        "prove".as_ref(), "--keys".as_ref(), keys.as_os_str(), "--input".as_ref(), inputs.as_os_str(), "--proof".as_ref(), proof.as_os_str(),
        "--pk-format".as_ref(), key_loading.format.as_ref(), "--pk-check".as_ref(), key_loading.check.as_ref(),
    ];
    if hide_issuer {
        prove_args.extend(["--issuers".as_ref(), issuers_pem.as_os_str()]);
    }
    let tsa_pem = work_dir.join(c2pa_x509_zk_demo::third_party::eligible_issuers_file(c2pa_x509_zk_demo::trust::Purpose::TimeStamping));
    if hide_time_stamp {
        prove_args.extend(["--tsa-issuers".as_ref(), tsa_pem.as_os_str(), "--window".as_ref(), "86400".as_ref()]);
    }
    let verify_args = ["verify".as_ref(), "--keys".as_ref(), keys.as_os_str(), "--public".as_ref(), public.as_os_str(), "--proof".as_ref(), proof.as_os_str()];

    if external.is_none() {
        run_phase(&mut phases, "fixtures", "test-fixture", &mut phase_cmd("tp-fixtures"))?;
    } else {
        phases.push(json!({ "name": "fixtures", "category": "test-fixture", "skipped": "external asset" }));
    }
    if keys_given(work_dir, &keys) {
        phases.push(json!({ "name": "setup", "category": "one-time", "skipped": "reused existing keys" }));
    } else {
        let statement = if hide_time_stamp { VARIANT_HIDDEN_ALL } else if hide_issuer { VARIANT_HIDDEN_ISSUER } else { "disclosed" };
        phases.push(gnark_phase("setup", "one-time", &mut gnark_cmd(&["setup".as_ref(), "--keys".as_ref(), keys.as_os_str(), "--curve".as_ref(), curve.as_ref(), "--statement".as_ref(), statement.as_ref()]))?);
    }
    let keys_variant = keys_manifest(&keys)?["variant"].as_str().unwrap_or("disclosed").to_string();
    let expected = if hide_time_stamp { VARIANT_HIDDEN_ALL } else if hide_issuer { VARIANT_HIDDEN_ISSUER } else { "disclosed" };
    if keys_variant != expected {
        bail!("the run is for the {expected} statement, but the keys in {} are for the {keys_variant} statement", keys.display());
    }
    run_phase(&mut phases, "prepare", "anonymization", &mut phase_cmd("tp-prepare"))?;

    phases.push(prove_runs("prove", "anonymization", true, reps, &keys, files, || gnark_cmd(&prove_args))?);
    phases.push(gnark_phase("self_verify", "anonymization", &mut gnark_cmd(&verify_args))?);
    run_phase(&mut phases, "package", "anonymization", &mut phase_cmd("tp-package"))?;
    phases.push(gnark_phase("verify", "verification", &mut gnark_cmd(&verify_args))?);
    let mut verify_cli = Command::new(exe.with_file_name("c2pa-x509-zk-verify"));
    verify_cli
        .arg("--input").arg(&paths.anonymized)
        .arg("--trust-list").arg(&paths.trust_list)
        .arg("--tsa-trust-list").arg(&paths.tsa_trust_list)
        .arg("--keys").arg(&keys).arg("--gnark").arg(gnark);
    if hide_issuer {
        verify_cli.arg("--issuer-policy").arg(work_dir.join("policy.json"));
    }
    run_phase(&mut phases, "verify_cli", "verification-full", &mut verify_cli)?;
    // Warm runs: read the files once so they are resident, then prove.
    for file in files {
        std::io::copy(&mut std::fs::File::open(keys.join(file))?, &mut std::io::sink())?;
    }
    phases.push(prove_runs("prove_warm", "supplementary", false, reps, &keys, files, || gnark_cmd(&prove_args))?);

    let data_of = |name: &str| phases.iter().find(|p| p["name"] == name).map(|p| p["data"].clone()).unwrap_or(Value::Null);
    let (prepare, package) = (data_of("prepare"), data_of("package"));
    // The per-asset figure carries the prove phase's observed cache state: it
    // is a cold measurement only when that says "cold".
    let mut per_asset = total(&phases, &["prepare", "prove", "self_verify", "package"]);
    per_asset["prove_cache"] = data_of("prove")["cache"].clone();
    let manifest = keys_manifest(&keys)?;
    let statement = if hide_time_stamp { VARIANT_HIDDEN_ALL } else if hide_issuer { VARIANT_HIDDEN_ISSUER } else { "disclosed" };
    let max_claim = manifest["sizes"]["MaxClaim"].as_u64().ok_or_else(|| anyhow!("the keys' manifest has no MaxClaim size"))?;
    let size = |f: &str| std::fs::metadata(keys.join(f)).map(|m| m.len()).unwrap_or(0);

    Ok(json!({
        "schema": "c2pa-x509-zk-bench/2",
        "variant": {
            "mode": "third-party",
            "trust_model": "A",
            "signer_key": "P-256 (ES256 claim signature)",
            "ca_signature": "ECDSA P-384 with SHA-384",
            "time_stamp": if hide_time_stamp {
                "sigTst2, token verified in the circuit (TSA hidden in the TSA tree; time disclosed as a window)"
            } else {
                "sigTst2, imprint bound in the circuit, token verified off-circuit"
            },
            "proof_system": "Groth16 (gnark v0.16.4, native Go witness solving, one BSB22 commitment)",
            "proving_key": { "format": key_loading.format, "point_checks": key_loading.check, "file_sha256_checked": true },
            "curve": manifest["curve"].as_str().unwrap_or(DEFAULT_CURVE),
            "circuit": if hide_time_stamp { "gnark/statement HiddenAllCircuit (third-party-hidden/1)" } else if hide_issuer { "gnark/statement HiddenIssuerCircuit (third-party-hidden-issuer/1)" } else { "gnark/statement (third-party/1)" },
            "time_stamp_hidden": hide_time_stamp,
            "issuer": if hide_issuer { json!({ "hidden": true, "tree": "issuertree format 1 (Poseidon2, depth 8)", "entries": prepare["issuer_tree_entries"] }) } else { json!({ "hidden": false }) },
        },
        "statement": match statement {
            VARIANT_HIDDEN_ALL => STATEMENT_HIDDEN_ALL,
            VARIANT_HIDDEN_ISSUER => STATEMENT_HIDDEN_ISSUER,
            _ => STATEMENT,
        },
        "accounting": ACCOUNTING,
        "environment": environment,
        "artifacts": {
            "constraints": manifest["constraints"],
            "sizes": manifest["sizes"],
            "verifying_key_sha256": manifest["sha256"]["statement.vk"],
            "constraint_system_bytes": size("statement.ccs"),
            "proving_key_bytes": size(key_loading.proving_key_file()),
            "verifying_key_bytes": size("statement.vk"),
            "gnark_cli_sha256": file_sha256(gnark)?,
        },
        "inputs": {
            "claim_bytes": prepare["claim_bytes"],
            "protected_header_bytes": prepare["protected_header_bytes"],
            "signer_certificate_bytes": prepare["signer_certificate_bytes"],
            "tbs_certificate_bytes": prepare["tbs_certificate_bytes"],
            "issuing_chain_certificates": prepare["issuing_chain_certificates"],
            "asset": if external.is_some() { json!({ "source": "external", "file": identify(&paths.signed)? }) } else { json!({ "source": "fixture (mirror PKI, local TSA)", "unsigned_bytes": std::fs::metadata(zk_root.join("fixtures/cards.png"))?.len() }) },
            "trust_list": identify(&paths.trust_list)?,
            "tsa_trust_list": identify(&paths.tsa_trust_list)?,
        },
        "totals": {
            "one_time": total(&phases, &["setup"]),
            "anonymization_per_asset": per_asset,
            "anonymization_witness_plus_prove": total(&phases, &["prove"]),
            "verification": total(&phases, &["verify"]),
            "verification_full": total(&phases, &["verify_cli"]),
        },
        "phases": phases,
        "output": {
            "proof_bytes": package["proof_bytes"],
            "public_inputs": public_inputs(statement, max_claim),
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

    fn run(wall: f64, peak: f64, cache: &str, load: f64) -> Value {
        json!({ "wall_s": wall, "peak_rss_mib": peak, "cache": cache, "steps": { "load_proving_key_s": load } })
    }

    #[test]
    fn aggregation_keeps_the_median_run_whole_and_the_maximum_peak() {
        // The median run by wall time is 79.4 s; its steps come with it, even
        // though another run has the median load time.
        let runs = vec![run(79.5, 7000.0, "cold", 58.0), run(78.6, 7700.0, "cold", 60.1), run(79.4, 7100.0, "cold", 59.0)];
        let phase = aggregate_runs("prove", "anonymization", runs);
        assert_eq!(phase["wall_s"], json!(79.4));
        assert_eq!(phase["steps"]["load_proving_key_s"], json!(59.0));
        assert_eq!(phase["peak_rss_mib"], json!(7700.0));
        assert_eq!(phase["data"]["cache"], json!("cold"));
        assert_eq!(phase["data"]["runs"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn aggregation_reports_the_observed_cache_state() {
        let failed = aggregate_runs("prove", "anonymization", vec![run(70.0, 1.0, "eviction-failed", 1.0)]);
        assert_eq!(failed["data"]["cache"], json!("eviction-failed"));
        let mixed = aggregate_runs("prove", "anonymization", vec![run(70.0, 1.0, "cold", 1.0), run(71.0, 1.0, "eviction-failed", 1.0)]);
        assert_eq!(mixed["data"]["cache"], json!("mixed"));
        assert_eq!(mixed["data"]["runs"][1]["cache"], json!("eviction-failed"));
    }

    #[test]
    fn public_inputs_follow_the_statement() {
        // As the verifying keys expect, without gnark's commitment input.
        assert_eq!(public_inputs("disclosed", 1024), 50);
        assert_eq!(public_inputs(VARIANT_HIDDEN_ISSUER, 1024), 39);
        assert_eq!(public_inputs(VARIANT_HIDDEN_ALL, 1024), 39);
    }

    #[test]
    fn parses_the_gnark_cli_timings() {
        let stderr = "load constraint system: 1.27 s\nread proving key: 0.9 s\nhash proving key: 2.1 s\nparse proving key: 57.6 s\nload proving key: 60.71 s\n\
                      \u{1b}[90m15:44:08\u{1b}[0m DBG constraint system solver done \u{1b}[36mnbConstraints=\u{1b}[0m4710762 \u{1b}[36mtook=\u{1b}[0m2056.566974\n\
                      prove: 18.49 s\nerror: something: 3 s\n";
        let steps = gnark_steps(stderr);
        assert_eq!(steps["load_constraint_system_s"], json!(1.27));
        assert_eq!(steps["load_proving_key_s"], json!(60.71));
        assert_eq!(steps["prove_s"], json!(18.49));
        assert_eq!(steps["solve_s"], json!(2.056566974));
        assert_eq!((steps["read_proving_key_s"].clone(), steps["hash_proving_key_s"].clone(), steps["parse_proving_key_s"].clone()), (json!(0.9), json!(2.1), json!(57.6)));
        assert!(!steps.contains_key("error_s") && steps.len() == 7, "{steps:?}");
    }
}

/// Whether the keys directory was given (outside the work directory) rather than created by this run.
fn keys_given(work_dir: &Path, keys: &Path) -> bool {
    !keys.starts_with(work_dir)
}
