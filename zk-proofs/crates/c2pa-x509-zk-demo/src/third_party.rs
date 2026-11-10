//! Inputs for the third-party statement's prover (roadmap E2b; the circuit is
//! the Go package `gnark/statement`, run by the `c2pa-zk-gnark` CLI).
//!
//! From a signed asset: the original claim signature's parts, the issuing CA
//! (the first certificate on the signer's validated path to the trust list,
//! at the time-stamp's time), and the time stamp's attested time and imprint.
//! The time stamp is required (THIRD-PARTY-STATEMENT.md, Q6) and, for now,
//! must be `sigTst2` (Q10).

use crate::jumbf::{active_assertions, active_manifest, manifest_count, manifest_store, ActiveManifest};
use crate::original_signature::{tst_info, OriginalSignature, TimeStampVersion, COSE_ALG_ES256, SHA256_OID};
use crate::trust::{issuing_path_for, validate_issuing_chain, TrustList};
use crate::zk_signature::{proof_len, ZkSignature, DEFAULT_CURVE};
use anyhow::{anyhow, bail, Context, Result};
use ciborium::Value;
use std::path::PathBuf;
use std::process::Command;
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// What the verifier derives from the anonymized asset.
#[derive(Debug, Clone, Serialize)]
pub struct PublicInputs {
    /// The claim (base64).
    pub claim: String,
    /// The issuing CA certificate, DER (base64).
    pub issuer_certificate: String,
    /// The time stamp's attested time, Unix seconds.
    pub time: u64,
    /// The time stamp's SHA-256 message imprint (base64).
    pub imprint: String,
}

/// The prover's inputs: the public ones and the original signature's parts.
#[derive(Debug, Clone, Serialize)]
pub struct StatementInputs {
    #[serde(flatten)]
    pub public: PublicInputs,
    /// The original protected header (base64).
    pub protected: String,
    /// The original claim signature, r || s (base64).
    pub signature: String,
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Unix seconds of a GeneralizedTime `YYYYMMDDHHMMSS[.fraction]Z`; the
/// fraction is dropped.
pub fn generalized_time_unix(s: &str) -> Result<u64> {
    let digits = s.strip_suffix('Z').ok_or_else(|| anyhow!("time {s:?} is not in UTC"))?;
    let whole = digits.split('.').next().unwrap_or_default();
    if whole.len() != 14 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        bail!("malformed GeneralizedTime {s:?}");
    }
    let n = |r: std::ops::Range<usize>| whole[r].parse::<u16>().expect("digits");
    let dt = der::DateTime::new(n(0..4), n(4..6) as u8, n(6..8) as u8, n(8..10) as u8, n(10..12) as u8, n(12..14) as u8)
        .map_err(|e| anyhow!("invalid time {s:?}: {e}"))?;
    Ok(dt.unix_duration().as_secs())
}

/// Prepare the prover's inputs from a signed asset.
pub fn statement_inputs(asset: &Path, trust: &TrustList) -> Result<StatementInputs> {
    Ok(prepare(&OriginalSignature::from_asset(asset)?, trust)?.0)
}

/// The prover's inputs, and the validated issuing path (issuing CA first,
/// ending at the trust anchor) at the time stamp's time.
fn prepare(original: &OriginalSignature, trust: &TrustList) -> Result<(StatementInputs, Vec<Vec<u8>>)> {
    if original.alg != COSE_ALG_ES256 {
        bail!("claim signature alg {} is not ES256, the only one the statement supports", original.alg);
    }
    let ts = original.time_stamp.as_ref().ok_or_else(|| anyhow!("the claim signature has no time stamp, which the statement requires"))?;
    if ts.version != TimeStampVersion::V2 {
        bail!("the time stamp is sigTst (v1); the statement supports sigTst2 (v2) for now");
    }
    let info = tst_info(&ts.token)?;
    let countersignature = original.countersignature_structure(TimeStampVersion::V2);
    if info.hash_algorithm_oid != SHA256_OID || info.hashed_message[..] != Sha256::digest(&countersignature)[..] {
        bail!("the time stamp's imprint is not the SHA-256 of the signature's countersignature structure");
    }
    let time = generalized_time_unix(&info.gen_time)?;

    let leaf = original.signer_certificate()?;
    let chain = issuing_path_for(leaf, &original.x5chain[1..], trust, time)?;
    let issuer = chain.first().ok_or_else(|| anyhow!("empty issuing path"))?;

    let inputs = StatementInputs {
        public: PublicInputs {
            claim: b64(&original.manifest.claim),
            issuer_certificate: b64(issuer),
            time,
            imprint: b64(&info.hashed_message),
        },
        protected: b64(&original.protected),
        signature: b64(&original.signature),
    };
    Ok((inputs, chain))
}

// ---- The claim (Q9) ----------------------------------------------------------

/// What stays visible in the anonymized asset (THIRD-PARTY-STATEMENT.md, Q9).
#[derive(Debug, Clone, Default)]
pub struct ClaimReport {
    /// The claim generator's name (and version, if given).
    pub claim_generator: String,
    /// The labels of the claim's assertions, all of which stay visible and
    /// authenticated.
    pub assertions: Vec<String>,
    /// Byte ranges (start, length) the hard binding excludes. One holds the
    /// manifest store; any other holds data (for example EXIF or XMP) that
    /// neither the claim nor the proof authenticates.
    pub hard_binding_exclusions: Vec<(u64, u64)>,
}

/// Check the claim against Q9 and report what stays visible. Refused: more
/// than one manifest (ingredients' manifests carry other signers'
/// certificates), identity assertions, and ingredient assertions.
pub fn check_claim(store: &[u8], claim: &[u8]) -> Result<ClaimReport> {
    if manifest_count(store)? != 1 {
        bail!("the asset has more than one manifest (ingredients' manifests name their signers); anonymizing multi-manifest provenance is out of scope");
    }
    let value: Value = ciborium::from_reader(claim)?;
    let map = value.as_map().ok_or_else(|| anyhow!("the claim is not a map"))?;
    let get = |key: &str| map.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v);
    let mut report = ClaimReport::default();
    for key in ["created_assertions", "gathered_assertions", "assertions"] {
        for entry in get(key).and_then(Value::as_array).into_iter().flatten() {
            let url = entry
                .as_map()
                .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("url")))
                .and_then(|(_, v)| v.as_text())
                .ok_or_else(|| anyhow!("malformed assertion reference in the claim"))?;
            let label = url.rsplit('/').next().unwrap_or(url).to_string();
            if label.starts_with("cawg.identity") {
                bail!("the claim has an identity assertion ({label}), which identifies the signer by design");
            }
            if label.starts_with("c2pa.ingredient") {
                bail!("the claim has an ingredient ({label}); anonymizing provenance with ingredients is out of scope");
            }
            report.assertions.push(label);
        }
    }
    report.claim_generator = get("claim_generator_info")
        .and_then(|v| match v {
            Value::Array(items) => items.first().cloned(),
            other => Some(other.clone()),
        })
        .and_then(|info| {
            let m = info.as_map()?.clone();
            let field = |k: &str| m.iter().find(|(key, _)| key.as_text() == Some(k)).and_then(|(_, v)| v.as_text().map(str::to_string));
            Some(match (field("name"), field("version")) {
                (Some(n), Some(v)) => format!("{n} {v}"),
                (Some(n), None) => n,
                _ => String::new(),
            })
        })
        .or_else(|| get("claim_generator").and_then(Value::as_text).map(str::to_string))
        .unwrap_or_default();
    for assertion in active_assertions(store)? {
        if assertion.label == "c2pa.hash.data" && &assertion.content_type == b"cbor" {
            let hash: Value = ciborium::from_reader(assertion.content.as_slice())?;
            let exclusions = hash
                .as_map()
                .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("exclusions")))
                .and_then(|(_, v)| v.as_array().cloned())
                .unwrap_or_default();
            for exclusion in exclusions {
                let field = |k: &str| {
                    exclusion
                        .as_map()
                        .and_then(|m| m.iter().find(|(key, _)| key.as_text() == Some(k)))
                        .and_then(|(_, v)| v.as_integer())
                        .and_then(|i| u64::try_from(i).ok())
                };
                if let (Some(start), Some(length)) = (field("start"), field("length")) {
                    report.hard_binding_exclusions.push((start, length));
                }
            }
        }
    }
    Ok(report)
}

// ---- The gnark CLI ------------------------------------------------------------

/// The `c2pa-zk-gnark` CLI and its key directory (from `c2pa-zk-gnark setup`).
#[derive(Debug, Clone)]
pub struct Prover {
    pub cli: PathBuf,
    pub keys: PathBuf,
}

impl Prover {
    fn manifest(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(
            &std::fs::read(self.keys.join("keys.json")).with_context(|| format!("no keys.json in {} (run c2pa-zk-gnark setup)", self.keys.display()))?,
        )?)
    }

    /// SHA-256 (hex) of the verifying key, from the key directory's keys.json.
    pub fn vk_sha256(&self) -> Result<String> {
        self.manifest()?["sha256"]["statement.vk"].as_str().map(str::to_string).ok_or_else(|| anyhow!("keys.json has no verifying-key hash"))
    }

    /// The key set's curve, from keys.json (BN254 when absent).
    pub fn curve(&self) -> Result<String> {
        let curve = self.manifest()?["curve"].as_str().unwrap_or(DEFAULT_CURVE).to_string();
        proof_len(&curve)?;
        Ok(curve)
    }

    fn run(&self, args: &[&std::ffi::OsStr]) -> Result<std::process::Output> {
        Command::new(&self.cli).args(args).output().with_context(|| format!("failed to run {}", self.cli.display()))
    }

    /// Prove, returning the proof bytes.
    pub fn prove(&self, inputs: &StatementInputs) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir()?;
        let (input, proof) = (dir.path().join("inputs.json"), dir.path().join("proof.bin"));
        std::fs::write(&input, serde_json::to_vec(inputs)?)?;
        let out = self.run(&["prove".as_ref(), "--keys".as_ref(), self.keys.as_os_str(), "--input".as_ref(), input.as_os_str(), "--proof".as_ref(), proof.as_os_str()])?;
        if !out.status.success() {
            bail!("proving failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(std::fs::read(proof)?)
    }

    /// Verify a proof against public inputs: Ok(true) valid, Ok(false) invalid.
    pub fn verify(&self, public: &PublicInputs, proof: &[u8]) -> Result<bool> {
        let dir = tempfile::tempdir()?;
        let (input, proof_path) = (dir.path().join("public.json"), dir.path().join("proof.bin"));
        std::fs::write(&input, serde_json::to_vec(public)?)?;
        std::fs::write(&proof_path, proof)?;
        let out = self.run(&["verify".as_ref(), "--keys".as_ref(), self.keys.as_os_str(), "--public".as_ref(), input.as_os_str(), "--proof".as_ref(), proof_path.as_os_str()])?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => bail!("verification failed to run: {}", String::from_utf8_lossy(&out.stderr).trim()),
        }
    }
}

// ---- Anonymize ------------------------------------------------------------------

/// What the anonymizer did and what stays visible.
#[derive(Debug, Clone)]
pub struct AnonymizeReport {
    pub claim: ClaimReport,
    /// The issuing chain embedded in x5chain.
    pub issuing_chain: Vec<Vec<u8>>,
    pub time: u64,
    /// The claim signature's size, unchanged.
    pub signature_bytes: usize,
    /// Padding left in the ZK signature.
    pub spare_bytes: usize,
}

/// The asset with the active manifest's claim signature replaced by `cose`
/// (same length). Fails if the format's writer would change the asset's size,
/// as c2pa-rs does for TIFF-based formats (TIFF, DNG): the hard binding would
/// no longer match.
fn rewrite_asset(input: &Path, store: &[u8], manifest: &ActiveManifest, cose: &[u8]) -> Result<Vec<u8>> {
    if cose.len() != manifest.cose_sign1_range.len() {
        bail!("the replacement signature is {} bytes, not {}", cose.len(), manifest.cose_sign1_range.len());
    }
    let mut updated = store.to_vec();
    updated[manifest.cose_sign1_range.clone()].copy_from_slice(cose);
    let format = input.extension().and_then(|e| e.to_str()).ok_or_else(|| anyhow!("{} has no file extension", input.display()))?;
    let asset = std::fs::read(input)?;
    let written = c2pa::jumbf_io::save_jumbf_to_memory(format, &asset, &updated).map_err(|e| anyhow!("failed to write the manifest store: {e}"))?;
    if written.len() != asset.len() {
        bail!("rewriting the manifest store changes the asset's size, so the hard binding would not match; this format is not supported (for example TIFF and DNG)");
    }
    Ok(written)
}

/// Replace the active manifest's claim signature with `cose` (same length)
/// and write the asset with the updated store.
pub fn replace_signature(input: &Path, output: &Path, store: &[u8], manifest: &ActiveManifest, cose: &[u8]) -> Result<()> {
    std::fs::write(output, rewrite_asset(input, store, manifest, cose)?)?;
    Ok(())
}

/// Anonymize a signed asset in third-party mode: prove the statement for its
/// original signature, then replace that signature in place.
pub fn anonymize(input: &Path, output: &Path, trust: &TrustList, prover: &Prover) -> Result<AnonymizeReport> {
    let store = manifest_store(input)?;
    let manifest = active_manifest(&store)?;
    let claim = check_claim(&store, &manifest.claim)?;
    let original = OriginalSignature::from_manifest(manifest.clone())?;
    let (inputs, issuing_chain) = prepare(&original, trust)?;
    let token = original.time_stamp.as_ref().map(|t| t.token.clone()).ok_or_else(|| anyhow!("no time stamp"))?;

    // The ZK signature must fit the original's space: check before proving.
    let size = manifest.cose_sign1.len();
    let curve = prover.curve()?;
    let expected_len = proof_len(&curve)?;
    let mut signature = ZkSignature { issuing_chain: issuing_chain.clone(), vk_sha256: prover.vk_sha256()?, curve, time_stamp_token: token, proof: vec![0; expected_len] };
    signature.encode_exact(size)?;
    let spare_bytes = size - signature.encode(0, 0).len();
    // The format must allow rewriting the store at the same size: try it with
    // the original signature, also before proving.
    rewrite_asset(input, &store, &manifest, &manifest.cose_sign1)?;

    signature.proof = prover.prove(&inputs)?;
    if signature.proof.len() != expected_len {
        bail!("the proof is {} bytes, not {expected_len}", signature.proof.len());
    }
    // Check the proof before embedding it.
    if !prover.verify(&inputs.public, &signature.proof)? {
        bail!("the new proof does not verify");
    }
    replace_signature(input, output, &store, &manifest, &signature.encode_exact(size)?)?;
    Ok(AnonymizeReport { claim, issuing_chain, time: inputs.public.time, signature_bytes: size, spare_bytes })
}

// ---- Verify ---------------------------------------------------------------------

/// Whether the asset's active manifest carries a third-party ZK signature.
pub fn is_third_party(asset: &Path) -> bool {
    manifest_store(asset)
        .and_then(|store| active_manifest(&store))
        .map(|m| ZkSignature::is_declared(&m.cose_sign1))
        .unwrap_or(false)
}

/// What a successful verification established.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub claim: ClaimReport,
    /// The issuing CA's subject.
    pub issuer: String,
    /// The validated path, issuing CA first, ending at the trust anchor.
    pub path: Vec<Vec<u8>>,
    /// The time stamp's attested time (Unix seconds).
    pub time: u64,
    /// The c2pa validation codes for the claim's assertions and binding.
    pub c2pa_success: Vec<String>,
}

/// Validate an RFC 3161 token with OpenSSL: its signature, its TSA
/// certificate's chain to `tsa_trust` (with the timeStamping purpose) at time
/// `at`, and that it attests `imprint`.
pub fn verify_time_stamp(token: &[u8], imprint: &[u8], tsa_trust: &Path, at: u64) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("token.der");
    std::fs::write(&path, token)?;
    let out = Command::new("openssl")
        .args(["ts", "-verify", "-token_in", "-in"])
        .arg(&path)
        .args(["-digest", &hex::encode(imprint), "-attime", &at.to_string(), "-CAfile"])
        .arg(tsa_trust)
        .output()
        .context("failed to run openssl")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !stdout.contains("Verification: OK") {
        bail!("the time-stamp token does not verify against the TSA trust list: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// The c2pa validation of the claim's assertions and hard binding. The
/// claim signature itself is the ZK signature, which c2pa cannot validate;
/// its failure codes are expected and ignored, every other failure is not.
pub fn c2pa_claim_checks(asset: &Path) -> Result<Vec<String>> {
    let settings = serde_json::json!({ "verify": { "verify_trust": false, "verify_timestamp_trust": false } });
    let context = c2pa::Context::new().with_settings(settings)?;
    let format = asset.extension().and_then(|e| e.to_str()).unwrap_or_default().to_string();
    let reader = c2pa::Reader::from_context(context).with_stream(&format, std::fs::File::open(asset)?)?;
    let active = reader.validation_results().and_then(|r| r.active_manifest()).ok_or_else(|| anyhow!("c2pa reported no validation results"))?;
    let codes = |s: &[c2pa::validation_status::ValidationStatus]| s.iter().map(|v| v.code().to_string()).collect::<Vec<_>>();
    let expected = |code: &str| code.starts_with("claimSignature.") || code.starts_with("signingCredential.") || code.starts_with("algorithm.") || code.starts_with("timeStamp.");
    let unexpected: Vec<String> = codes(active.failure()).into_iter().filter(|c| !expected(c)).collect();
    if !unexpected.is_empty() {
        bail!("c2pa validation failed: {}", unexpected.join(", "));
    }
    let success = codes(active.success());
    const HARD_BINDING_MATCH: [&str; 4] = ["assertion.dataHash.match", "assertion.bmffHash.match", "assertion.boxesHash.match", "assertion.collectionHash.match"];
    if !success.iter().any(|c| HARD_BINDING_MATCH.contains(&c.as_str())) {
        bail!("c2pa did not validate the claim's hard binding: {}", success.join(", "));
    }
    Ok(success)
}

/// Verify a third-party anonymized asset: the issuing chain and time stamp
/// off-circuit, the claim's assertions and hard binding with c2pa, and the
/// proof with public inputs all derived from the asset. With
/// `expected_issuer`, the issuing CA's subject DN must equal it.
pub fn verify(asset: &Path, trust: &TrustList, tsa_trust: &Path, prover: &Prover, expected_issuer: Option<&str>) -> Result<VerifyReport> {
    let store = manifest_store(asset)?;
    let manifest = active_manifest(&store)?;
    let signature = ZkSignature::decode(&manifest.cose_sign1)?;
    let keys_curve = prover.curve()?;
    if signature.curve != keys_curve {
        bail!("the proof is on {}, but the keys in {} are for {keys_curve}", signature.curve, prover.keys.display());
    }
    if signature.vk_sha256 != prover.vk_sha256()? {
        bail!("the proof was made with other keys (verifying key {}), not those in {}", signature.vk_sha256, prover.keys.display());
    }
    let claim = check_claim(&store, &manifest.claim)?;

    let info = tst_info(&signature.time_stamp_token)?;
    if info.hash_algorithm_oid != SHA256_OID {
        bail!("the time stamp's imprint is not SHA-256");
    }
    let time = generalized_time_unix(&info.gen_time)?;
    verify_time_stamp(&signature.time_stamp_token, &info.hashed_message, tsa_trust, time)?;

    let path = validate_issuing_chain(&signature.issuing_chain, trust, time)?;
    let issuer = &signature.issuing_chain[0];
    let issuer_dn = crate::extract_subject_dn(issuer)?;
    if let Some(expected) = expected_issuer {
        if issuer_dn != expected {
            bail!("the issuing CA is {issuer_dn}, not the expected {expected}");
        }
    }
    let c2pa_success = c2pa_claim_checks(asset)?;

    let public = PublicInputs { claim: b64(&manifest.claim), issuer_certificate: b64(issuer), time, imprint: b64(&info.hashed_message) };
    if !prover.verify(&public, &signature.proof)? {
        bail!("the proof does not verify for this asset's claim, issuing CA, and time stamp");
    }
    Ok(VerifyReport { claim, issuer: issuer_dn, path, time, c2pa_success })
}
