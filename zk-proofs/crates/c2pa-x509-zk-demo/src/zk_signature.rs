//! The third-party ZK signature: the `COSE_Sign1` that replaces the original
//! claim signature in place (THIRD-PARTY-STATEMENT.md, Q1, "The ZK
//! signature's encoding").
//!
//! - Protected header: `alg` -65538 (private use), `crit` ["c2pa-x509-zk"],
//!   `x5chain` with the issuing CA chain (never the signer's certificate), and
//!   "c2pa-x509-zk": {"statement": "third-party/1", "vk": SHA-256 of the
//!   verifying key}.
//! - Unprotected header: "c2pa-x509-zk-tst" with the original time stamp,
//!   unchanged (a private label: the token covers the original signature, not
//!   this one), then `pad` and `pad2` to reach the original's exact size.
//! - Payload `nil` (detached); signature: a format version byte, then the
//!   proof. Every public input of the proof is derived by the verifier.

use anyhow::{anyhow, bail, Result};
use ciborium::Value;

pub const ZK_ALG: i64 = -65538;
pub const CRIT_LABEL: &str = "c2pa-x509-zk";
pub const STATEMENT: &str = "third-party/1";
pub const TIME_STAMP_LABEL: &str = "c2pa-x509-zk-tst";
pub const FORMAT_VERSION: u8 = 1;
/// A gnark Groth16 proof over BN254 with one commitment, compressed.
pub const PROOF_LEN: usize = 196;
const COSE_SIGN1_TAG: u64 = 18;

/// The third-party ZK signature's contents.
#[derive(Debug, Clone, PartialEq)]
pub struct ZkSignature {
    /// The issuing CA chain, issuing CA first.
    pub issuing_chain: Vec<Vec<u8>>,
    /// SHA-256 of the verifying key (hex), identifying the circuit and keys.
    pub vk_sha256: String,
    /// The original RFC 3161 time-stamp token (`sigTst2`).
    pub time_stamp_token: Vec<u8>,
    pub proof: Vec<u8>,
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR serialization to memory cannot fail");
    out
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

impl ZkSignature {
    /// The tagged `COSE_Sign1` with padding fields of the given lengths.
    pub fn encode(&self, pad: usize, pad2: usize) -> Vec<u8> {
        let protected = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(ZK_ALG.into())),
            (Value::Integer(2.into()), Value::Array(vec![text(CRIT_LABEL)])),
            (Value::Integer(33.into()), Value::Array(self.issuing_chain.iter().cloned().map(Value::Bytes).collect())),
            (
                text(CRIT_LABEL),
                Value::Map(vec![(text("statement"), text(STATEMENT)), (text("vk"), text(&self.vk_sha256))]),
            ),
        ]);
        let time_stamp = Value::Map(vec![(
            text("tstTokens"),
            Value::Array(vec![Value::Map(vec![(text("val"), Value::Bytes(self.time_stamp_token.clone()))])]),
        )]);
        let unprotected = Value::Map(vec![
            (text(TIME_STAMP_LABEL), time_stamp),
            (text("pad"), Value::Bytes(vec![0; pad])),
            (text("pad2"), Value::Bytes(vec![0; pad2])),
        ]);
        let signature = [&[FORMAT_VERSION][..], &self.proof].concat();
        cbor(&Value::Tag(
            COSE_SIGN1_TAG,
            Box::new(Value::Array(vec![Value::Bytes(cbor(&protected)), unprotected, Value::Null, Value::Bytes(signature)])),
        ))
    }

    /// The encoding padded to exactly `size` bytes, or an error if it does not
    /// fit. With both padding fields present every size from the unpadded one
    /// upward is reachable (a single field skips sizes where a CBOR length
    /// header grows).
    pub fn encode_exact(&self, size: usize) -> Result<Vec<u8>> {
        let unpadded = self.encode(0, 0).len();
        let Some(room) = size.checked_sub(unpadded) else {
            bail!("the ZK signature needs {unpadded} bytes, but the original signature has only {size}");
        };
        for pad2 in 0..=32 {
            // A pad of n bytes adds n plus its length header (0, 1, or 2 bytes
            // beyond the empty one), so the right length is just below the room.
            for pad in (room.saturating_sub(pad2 + 4)..=room).rev() {
                let encoded = self.encode(pad, pad2);
                if encoded.len() == size {
                    return Ok(encoded);
                }
            }
        }
        bail!("cannot pad the ZK signature to exactly {size} bytes")
    }

    /// Parse a third-party ZK signature; fails for any other `COSE_Sign1`.
    pub fn decode(cose: &[u8]) -> Result<Self> {
        let Value::Tag(COSE_SIGN1_TAG, inner) = ciborium::from_reader::<Value, _>(cose)? else {
            bail!("not a tagged COSE_Sign1");
        };
        let Value::Array(fields) = *inner else {
            bail!("COSE_Sign1 is not an array");
        };
        let [Value::Bytes(protected), Value::Map(unprotected), Value::Null, Value::Bytes(signature)] =
            <[Value; 4]>::try_from(fields).map_err(|_| anyhow!("COSE_Sign1 does not have four fields"))?
        else {
            bail!("malformed COSE_Sign1 fields (the payload must be detached)");
        };
        let Value::Map(header) = ciborium::from_reader::<Value, _>(protected.as_slice())? else {
            bail!("protected header is not a map");
        };
        if map_get(&header, &Value::Integer(1.into())) != Some(&Value::Integer(ZK_ALG.into())) {
            bail!("not a ZK signature (alg is not {ZK_ALG})");
        }
        if map_get(&header, &Value::Integer(2.into())) != Some(&Value::Array(vec![text(CRIT_LABEL)])) {
            bail!("the ZK extension is not marked critical");
        }
        let ext = map_get(&header, &text(CRIT_LABEL)).and_then(Value::as_map).ok_or_else(|| anyhow!("no ZK extension"))?;
        if map_get(ext, &text("statement")) != Some(&text(STATEMENT)) {
            bail!("not a third-party ZK signature (statement is not {STATEMENT})");
        }
        let vk_sha256 = map_get(ext, &text("vk")).and_then(Value::as_text).ok_or_else(|| anyhow!("no verifying-key hash"))?.to_string();
        let issuing_chain = map_get(&header, &Value::Integer(33.into()))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("no x5chain"))?
            .iter()
            .map(|c| c.as_bytes().cloned().ok_or_else(|| anyhow!("x5chain entry is not a byte string")))
            .collect::<Result<Vec<_>>>()?;
        if issuing_chain.is_empty() {
            bail!("x5chain is empty");
        }
        let tokens = map_get(&unprotected, &text(TIME_STAMP_LABEL))
            .and_then(Value::as_map)
            .and_then(|m| map_get(m, &text("tstTokens")))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("no time stamp"))?;
        let [token] = tokens.as_slice() else {
            bail!("the time-stamp header must hold exactly one token");
        };
        let time_stamp_token = token
            .as_map()
            .and_then(|m| map_get(m, &text("val")))
            .and_then(Value::as_bytes)
            .cloned()
            .ok_or_else(|| anyhow!("time-stamp token has no val"))?;
        let (&version, proof) = signature.split_first().ok_or_else(|| anyhow!("empty signature"))?;
        if version != FORMAT_VERSION {
            bail!("unsupported ZK signature format version {version}");
        }
        Ok(Self { issuing_chain, vk_sha256, time_stamp_token, proof: proof.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ZkSignature {
        ZkSignature {
            issuing_chain: vec![vec![0x30; 733]],
            vk_sha256: "ab".repeat(32),
            time_stamp_token: vec![0x30; 2000],
            proof: vec![7; PROOF_LEN],
        }
    }

    #[test]
    fn round_trips() {
        let z = sample();
        assert_eq!(ZkSignature::decode(&z.encode(10, 3)).unwrap(), z);
    }

    /// Every size from the unpadded one upward is reached exactly, across the
    /// CBOR length-header boundaries; a size below it is refused.
    #[test]
    fn pads_to_every_size_and_refuses_too_small() {
        let z = sample();
        let unpadded = z.encode(0, 0).len();
        for size in unpadded..unpadded + 600 {
            let encoded = z.encode_exact(size).unwrap_or_else(|e| panic!("{size}: {e}"));
            assert_eq!(encoded.len(), size);
            assert_eq!(ZkSignature::decode(&encoded).unwrap(), z);
        }
        let err = z.encode_exact(unpadded - 1).unwrap_err();
        assert!(err.to_string().contains("needs"), "{err}");
    }

    #[test]
    fn decode_rejects_other_signatures() {
        let z = sample();
        let good = z.encode(0, 0);
        assert!(ZkSignature::decode(&good[1..]).is_err());
        let mut versioned = z.clone();
        versioned.proof.clear();
        let mut bytes = versioned.encode(0, 0);
        let last = bytes.len() - 1;
        bytes[last] = 9; // format version 9, empty proof
        assert!(ZkSignature::decode(&bytes).is_err());
        let mut empty_chain = z;
        empty_chain.issuing_chain.clear();
        assert!(ZkSignature::decode(&empty_chain.encode(0, 0)).is_err());
    }
}
