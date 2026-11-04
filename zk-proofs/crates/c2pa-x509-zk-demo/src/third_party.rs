//! Inputs for the third-party statement's prover (roadmap E2b; the circuit is
//! the Go package `gnark/statement`, run by the `c2pa-zk-gnark` CLI).
//!
//! From a signed asset: the original claim signature's parts, the issuing CA
//! (the first certificate on the signer's validated path to the trust list,
//! at the time-stamp's time), and the time stamp's attested time and imprint.
//! The time stamp is required (THIRD-PARTY-STATEMENT.md, Q6) and, for now,
//! must be `sigTst2` (Q10).

use crate::original_signature::{tst_info, OriginalSignature, TimeStampVersion, COSE_ALG_ES256, SHA256_OID};
use crate::trust::{issuing_path_for, TrustList};
use anyhow::{anyhow, bail, Result};
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
    let original = OriginalSignature::from_asset(asset)?;
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

    Ok(StatementInputs {
        public: PublicInputs {
            claim: b64(&original.manifest.claim),
            issuer_certificate: b64(issuer),
            time,
            imprint: b64(&info.hashed_message),
        },
        protected: b64(&original.protected),
        signature: b64(&original.signature),
    })
}
