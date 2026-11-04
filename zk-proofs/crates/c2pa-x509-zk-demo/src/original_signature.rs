//! The original claim signature, as third-party anonymization sees it
//! (roadmap E2b; statement in THIRD-PARTY-STATEMENT.md).
//!
//! This is the off-circuit reference for what the circuit must hash and
//! verify: the claim signature's `Sig_structure` and the time stamp's
//! countersignature structure, rebuilt byte for byte from the asset. The
//! constructions match c2pa-rs and were checked against a real device-signed
//! asset (DEPLOYMENT-FINDINGS.md, "Anatomy of a real manifest").

use crate::jumbf::{active_manifest, manifest_store, ActiveManifest};
use anyhow::{anyhow, bail, Result};
use ciborium::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

/// COSE `alg` for ES256 (ECDSA P-256 with SHA-256).
pub const COSE_ALG_ES256: i64 = -7;
const COSE_HEADER_ALG: i64 = 1;
const COSE_HEADER_X5CHAIN: i64 = 33;
const COSE_SIGN1_TAG: u64 = 18;

/// Which C2PA time-stamp header carries the token (§10.3.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeStampVersion {
    /// `sigTst` (deprecated): countersigns the claim.
    V1,
    /// `sigTst2`: countersigns the serialized signature byte string.
    V2,
}

/// An RFC 3161 time stamp from the unprotected header.
#[derive(Debug, Clone)]
pub struct TimeStamp {
    pub version: TimeStampVersion,
    /// The value as stored: a `TimeStampResp` for `sigTst` (v1), a
    /// `TimeStampToken` for `sigTst2` (v2) (C2PA §10.3.2.5.4).
    pub stored: Vec<u8>,
    /// The `TimeStampToken` (CMS `ContentInfo`), DER, for either version.
    pub token: Vec<u8>,
}

/// What a time-stamp token attests: the hashed message and the time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TstInfo {
    /// The message imprint's hash algorithm (DER of the OID's value).
    pub hash_algorithm_oid: Vec<u8>,
    /// The message imprint's hash.
    pub hashed_message: Vec<u8>,
    /// `genTime` as written (GeneralizedTime, for example `20261104175228Z`).
    pub gen_time: String,
}

/// The original claim signature and the claim it covers.
#[derive(Debug, Clone)]
pub struct OriginalSignature {
    pub manifest: ActiveManifest,
    /// The protected header's serialized bytes, exactly as signed.
    pub protected: Vec<u8>,
    /// The protected header's `alg`.
    pub alg: i64,
    /// The protected header's `x5chain`: the signer certificate first.
    pub x5chain: Vec<Vec<u8>>,
    /// The signature value (for ECDSA, `r || s`).
    pub signature: Vec<u8>,
    pub time_stamp: Option<TimeStamp>,
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR serialization to memory cannot fail");
    out
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

impl OriginalSignature {
    pub fn from_asset(asset: &Path) -> Result<Self> {
        Self::from_manifest(active_manifest(&manifest_store(asset)?)?)
    }

    pub fn from_manifest(manifest: ActiveManifest) -> Result<Self> {
        let value: Value = ciborium::from_reader(manifest.cose_sign1.as_slice())?;
        let Value::Tag(COSE_SIGN1_TAG, inner) = value else {
            bail!("claim signature is not a tagged COSE_Sign1");
        };
        let Value::Array(fields) = *inner else {
            bail!("COSE_Sign1 is not an array");
        };
        let [Value::Bytes(protected), Value::Map(unprotected), payload, Value::Bytes(signature)] = <[Value; 4]>::try_from(fields)
            .map_err(|_| anyhow!("COSE_Sign1 does not have four fields"))?
        else {
            bail!("malformed COSE_Sign1 fields");
        };
        if payload != Value::Null {
            bail!("the claim signature's payload is not detached");
        }

        let Value::Map(header) = ciborium::from_reader::<Value, _>(protected.as_slice())? else {
            bail!("protected header is not a map");
        };
        let alg = match map_get(&header, &Value::Integer(COSE_HEADER_ALG.into())) {
            Some(Value::Integer(i)) => i64::try_from(*i)?,
            _ => bail!("protected header has no integer alg"),
        };
        let x5chain = match map_get(&header, &Value::Integer(COSE_HEADER_X5CHAIN.into())) {
            Some(Value::Array(certs)) => certs
                .iter()
                .map(|c| c.as_bytes().cloned().ok_or_else(|| anyhow!("x5chain entry is not a byte string")))
                .collect::<Result<Vec<_>>>()?,
            Some(Value::Bytes(cert)) => vec![cert.clone()],
            _ => bail!("protected header has no x5chain"),
        };
        if x5chain.is_empty() {
            bail!("x5chain is empty: no signer certificate");
        }

        let mut time_stamps = Vec::new();
        for (label, version) in [("sigTst", TimeStampVersion::V1), ("sigTst2", TimeStampVersion::V2)] {
            if let Some(value) = map_get(&unprotected, &Value::Text(label.into())) {
                let stored = single_token(value)?;
                let token = match version {
                    TimeStampVersion::V1 => time_stamp_token_from_response(&stored)?,
                    TimeStampVersion::V2 => stored.clone(),
                };
                time_stamps.push(TimeStamp { version, stored, token });
            }
        }
        if time_stamps.len() > 1 {
            bail!("more than one time stamp (C2PA §10.3.2.5.1 allows one)");
        }

        Ok(Self { manifest, protected, alg, x5chain, signature, time_stamp: time_stamps.pop() })
    }

    /// The signer certificate: the first `x5chain` entry (C2PA §13.5).
    pub fn signer_certificate(&self) -> Result<&[u8]> {
        self.x5chain.first().map(Vec::as_slice).ok_or_else(|| anyhow!("x5chain is empty: no signer certificate"))
    }

    /// `Sig_structure` for the claim signature: `["Signature1", protected,
    /// external_aad = h'', payload = claim]` (RFC 9052 §4.4; C2PA §10.3.2.4).
    pub fn sig_structure(&self) -> Vec<u8> {
        cbor(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(self.protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(self.manifest.claim.clone()),
        ]))
    }

    /// The structure the time stamp's message imprint hashes: `["CounterSignature",
    /// protected, h'', payload]`, where the payload is the claim (v1) or the
    /// serialized signature byte string, CBOR header included (v2).
    pub fn countersignature_structure(&self, version: TimeStampVersion) -> Vec<u8> {
        let payload = match version {
            TimeStampVersion::V1 => self.manifest.claim.clone(),
            TimeStampVersion::V2 => cbor(&Value::Bytes(self.signature.clone())),
        };
        cbor(&Value::Array(vec![
            Value::Text("CounterSignature".into()),
            Value::Bytes(self.protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(payload),
        ]))
    }

    /// Verify an ES256 claim signature with the signer certificate's key.
    pub fn verify_es256(&self) -> Result<()> {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::pkcs8::DecodePublicKey;
        use x509_cert::der::{Decode, Encode};
        if self.alg != COSE_ALG_ES256 {
            bail!("claim signature alg is {}, not ES256", self.alg);
        }
        let cert = x509_cert::Certificate::from_der(self.signer_certificate()?)?;
        let spki = cert.tbs_certificate.subject_public_key_info.to_der()?;
        let key = VerifyingKey::from_public_key_der(&spki).map_err(|e| anyhow!("signer key is not P-256: {e}"))?;
        let signature = Signature::from_slice(&self.signature).map_err(|e| anyhow!("malformed ES256 signature: {e}"))?;
        key.verify(&self.sig_structure(), &signature).map_err(|_| anyhow!("claim signature does not verify"))
    }
}

/// The one token in a `{"tstTokens": [{"val": bstr}]}` time-stamp header.
fn single_token(value: &Value) -> Result<Vec<u8>> {
    let tokens = value
        .as_map()
        .and_then(|m| map_get(m, &Value::Text("tstTokens".into())))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("time-stamp header has no tstTokens"))?;
    let [token] = tokens.as_slice() else {
        bail!("time-stamp header must hold exactly one token");
    };
    token
        .as_map()
        .and_then(|m| map_get(m, &Value::Text("val".into())))
        .and_then(Value::as_bytes)
        .cloned()
        .ok_or_else(|| anyhow!("time-stamp token has no val"))
}

/// One DER TLV: tag byte, content, and the bytes after it.
fn der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first().ok_or_else(|| anyhow!("truncated DER"))?;
    let (&first, rest) = rest.split_first().ok_or_else(|| anyhow!("truncated DER length"))?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            bail!("unsupported DER length");
        }
        (rest[..n].iter().fold(0usize, |acc, &b| acc << 8 | b as usize), &rest[n..])
    };
    if rest.len() < len {
        bail!("DER value runs past its container");
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn der_expect(input: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let (t, content, rest) = der_tlv(input)?;
    if t != tag {
        bail!("expected DER tag {tag:#04x}, found {t:#04x}");
    }
    Ok((content, rest))
}

/// The `TimeStampToken` in an RFC 3161 `TimeStampResp` (as `sigTst` stores
/// it): `SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }`. The
/// status must be granted (0) or granted with modifications (1), and the
/// token present.
pub fn time_stamp_token_from_response(response: &[u8]) -> Result<Vec<u8>> {
    let (body, trailing) = der_expect(response, 0x30)?;
    if !trailing.is_empty() {
        bail!("data after the TimeStampResp");
    }
    let (status_info, rest) = der_expect(body, 0x30)?;
    let (status, _) = der_expect(status_info, 0x02)?;
    if !matches!(status, [0] | [1]) {
        bail!("time-stamp response status {status:02x?} is not granted");
    }
    if rest.is_empty() {
        bail!("time-stamp response has no token");
    }
    let (tag, _, after) = der_tlv(rest)?;
    if tag != 0x30 || !after.is_empty() {
        bail!("malformed time-stamp token in the response");
    }
    Ok(rest.to_vec())
}

/// The `TSTInfo` of an RFC 3161 `TimeStampToken`: ContentInfo → [0] SignedData
/// → encapContentInfo → [0] OCTET STRING → TSTInfo. The token's CMS signature
/// is not checked here; c2pa (and, in E2b, the verifier) validates it.
pub fn tst_info(token: &[u8]) -> Result<TstInfo> {
    const SEQUENCE: u8 = 0x30;
    let (content_info, _) = der_expect(token, SEQUENCE)?;
    let (_content_type, rest) = der_expect(content_info, 0x06)?;
    let (explicit, _) = der_expect(rest, 0xa0)?;
    let (signed_data, _) = der_expect(explicit, SEQUENCE)?;
    let (_version, rest) = der_expect(signed_data, 0x02)?;
    let (_digest_algorithms, rest) = der_expect(rest, 0x31)?;
    let (encap, _) = der_expect(rest, SEQUENCE)?;
    let (_econtent_type, rest) = der_expect(encap, 0x06)?;
    let (explicit, _) = der_expect(rest, 0xa0)?;
    let (tst_der, _) = der_expect(explicit, 0x04)?;

    let (tst, _) = der_expect(tst_der, SEQUENCE)?;
    let (_version, rest) = der_expect(tst, 0x02)?;
    let (_policy, rest) = der_expect(rest, 0x06)?;
    let (imprint, rest) = der_expect(rest, SEQUENCE)?;
    let (algorithm, hashed) = der_expect(imprint, SEQUENCE)?;
    let (oid, _) = der_expect(algorithm, 0x06)?;
    let (hashed_message, _) = der_expect(hashed, 0x04)?;
    let (_serial, rest) = der_expect(rest, 0x02)?;
    let (gen_time, _) = der_expect(rest, 0x18)?;
    Ok(TstInfo {
        hash_algorithm_oid: oid.to_vec(),
        hashed_message: hashed_message.to_vec(),
        gen_time: String::from_utf8(gen_time.to_vec())?,
    })
}

/// DER value of the SHA-256 OID (2.16.840.1.101.3.4.2.1).
pub const SHA256_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// Whether `info`'s imprint is the SHA-256 of `message`.
pub fn imprint_matches_sha256(info: &TstInfo, message: &[u8]) -> bool {
    info.hash_algorithm_oid == SHA256_OID && info.hashed_message[..] == Sha256::digest(message)[..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;

    /// A tagged, detached COSE_Sign1 with an ES256 protected header holding
    /// `x5chain` and the given unprotected header.
    fn cose(x5chain: Value, unprotected: Vec<(Value, Value)>) -> ActiveManifest {
        let protected = cbor(&Value::Map(vec![
            (Value::Integer(COSE_HEADER_ALG.into()), Value::Integer(COSE_ALG_ES256.into())),
            (Value::Integer(COSE_HEADER_X5CHAIN.into()), x5chain),
        ]));
        let sign1 = cbor(&Value::Tag(
            COSE_SIGN1_TAG,
            Box::new(Value::Array(vec![Value::Bytes(protected), Value::Map(unprotected), Value::Null, Value::Bytes(vec![0; 64])])),
        ));
        let range: Range<usize> = 0..sign1.len();
        ActiveManifest { label: "urn:c2pa:test".into(), claim_label: "c2pa.claim.v2".into(), claim: b"claim".to_vec(), cose_sign1: sign1, cose_sign1_range: range }
    }

    fn certs(n: usize) -> Value {
        Value::Array((0..n).map(|_| Value::Bytes(vec![0x30, 0])).collect())
    }

    fn time_stamp_header(label: &str, tokens: Vec<Vec<u8>>) -> Vec<(Value, Value)> {
        let tokens = tokens.into_iter().map(|t| Value::Map(vec![(Value::Text("val".into()), Value::Bytes(t))])).collect();
        vec![(Value::Text(label.into()), Value::Map(vec![(Value::Text("tstTokens".into()), Value::Array(tokens))]))]
    }

    #[test]
    fn empty_or_malformed_x5chain_is_an_error_not_a_panic() {
        let err = OriginalSignature::from_manifest(cose(certs(0), vec![])).unwrap_err();
        assert!(err.to_string().contains("x5chain is empty"), "{err}");
        assert!(OriginalSignature::from_manifest(cose(Value::Array(vec![Value::Integer(1.into())]), vec![])).is_err());

        // A parsed signature whose chain is later emptied still fails cleanly.
        let mut parsed = OriginalSignature::from_manifest(cose(certs(1), vec![])).unwrap();
        parsed.x5chain.clear();
        assert!(parsed.signer_certificate().is_err());
        assert!(parsed.verify_es256().is_err());
    }

    #[test]
    fn time_stamp_headers_must_hold_exactly_one_token() {
        for tokens in [vec![], vec![vec![0x30, 0], vec![0x30, 0]]] {
            assert!(OriginalSignature::from_manifest(cose(certs(1), time_stamp_header("sigTst2", tokens))).is_err());
        }
    }

    #[test]
    fn v1_response_must_be_granted_and_hold_a_token() {
        // TimeStampResp { status = rejection (2) }, no token.
        let rejected = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        let err = OriginalSignature::from_manifest(cose(certs(1), time_stamp_header("sigTst", vec![rejected]))).unwrap_err();
        assert!(err.to_string().contains("not granted"), "{err}");
        // Granted, but no token.
        let empty = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(time_stamp_token_from_response(&empty).is_err());
        // Granted, with a (stand-in) token: the token is returned as is.
        let token = [0x30, 0x02, 0x05, 0x00];
        let response = [&[0x30, 0x09, 0x30, 0x03, 0x02, 0x01, 0x00][..], &token].concat();
        assert_eq!(time_stamp_token_from_response(&response).unwrap(), token);
        // A v2 header holds the token itself.
        let parsed = OriginalSignature::from_manifest(cose(certs(1), time_stamp_header("sigTst2", vec![token.to_vec()]))).unwrap();
        let ts = parsed.time_stamp.unwrap();
        assert_eq!((ts.version, ts.token.as_slice(), ts.stored.as_slice()), (TimeStampVersion::V2, &token[..], &token[..]));
    }
}
