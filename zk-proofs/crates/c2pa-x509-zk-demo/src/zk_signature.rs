//! The third-party ZK signature: the `COSE_Sign1` that replaces the original
//! claim signature in place (THIRD-PARTY-STATEMENT.md, Q1, "The ZK
//! signature's encoding").
//!
//! - Protected header: `alg` -65538 (private use), `crit` ["c2pa-x509-zk"],
//!   `x5chain` with the issuing CA chain (never the signer's certificate), and
//!   "c2pa-x509-zk": {"statement": "third-party/1", "vk": SHA-256 of the
//!   verifying key, and "curve" unless BN254 (roadmap E7)}.
//! - Unprotected header: "c2pa-x509-zk-tst" with the original time stamp,
//!   unchanged (a private label: the token covers the original signature, not
//!   this one), then `pad` and `pad2` to reach the original's exact size.
//! - Payload `nil` (detached); signature: a format version byte, then the
//!   proof. Every public input of the proof is derived by the verifier.
//!
//! Decoding is strict, so the format leaves no room for other data (a signer
//! certificate, say): exactly one CBOR item, exactly these header fields,
//! all-zero padding, and a proof of exactly its curve's length (`proof_len`).

use anyhow::{anyhow, bail, Result};
use ciborium::Value;

pub const ZK_ALG: i64 = -65538;
pub const CRIT_LABEL: &str = "c2pa-x509-zk";
pub const STATEMENT: &str = "third-party/1";
pub const TIME_STAMP_LABEL: &str = "c2pa-x509-zk-tst";
pub const FORMAT_VERSION: u8 = 1;
/// The default curve; signatures without a "curve" field use it.
pub const DEFAULT_CURVE: &str = "bn254";

/// The length of a gnark Groth16 proof with one commitment, compressed, on
/// each supported curve: A, B, C, the commitment and its proof of knowledge
/// (G1, G2, G1, G1, G1), plus a 4-byte count.
pub fn proof_len(curve: &str) -> Result<usize> {
    match curve {
        "bn254" => Ok(32 + 64 + 32 + 4 + 32 + 32),
        "bls12-381" => Ok(48 + 96 + 48 + 4 + 48 + 48),
        other => bail!("unsupported curve {other:?} (bn254 or bls12-381)"),
    }
}
const COSE_SIGN1_TAG: u64 = 18;

/// The third-party ZK signature's contents.
#[derive(Debug, Clone, PartialEq)]
pub struct ZkSignature {
    /// The issuing CA chain, issuing CA first.
    pub issuing_chain: Vec<Vec<u8>>,
    /// SHA-256 of the verifying key (hex), identifying the circuit and keys.
    pub vk_sha256: String,
    /// The proof system's curve ("bn254" or "bls12-381"; roadmap E7).
    pub curve: String,
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

/// Decode `bytes` as exactly one CBOR item, with nothing after it.
fn single_item(bytes: &[u8]) -> Result<Value> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor)?;
    if cursor.position() as usize != bytes.len() {
        bail!("{} bytes follow the CBOR item", bytes.len() - cursor.position() as usize);
    }
    Ok(value)
}

/// Every key of `map` is one of `allowed` (each at most once).
fn only_keys(map: &[(Value, Value)], allowed: &[Value], what: &str) -> Result<()> {
    for (i, (key, _)) in map.iter().enumerate() {
        if !allowed.contains(key) {
            bail!("unexpected field {key:?} in the {what}");
        }
        if map[..i].iter().any(|(k, _)| k == key) {
            bail!("duplicate field {key:?} in the {what}");
        }
    }
    Ok(())
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
                {
                    let mut ext = vec![(text("statement"), text(STATEMENT)), (text("vk"), text(&self.vk_sha256))];
                    // Written only for other curves, so BN254 signatures are unchanged.
                    if self.curve != DEFAULT_CURVE {
                        ext.push((text("curve"), text(&self.curve)));
                    }
                    Value::Map(ext)
                },
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

    /// Whether `cose` declares itself a third-party ZK signature (its `alg`
    /// and statement), without validating the rest: so that a malformed one
    /// is reported by `decode`'s errors rather than taken for another kind.
    pub fn is_declared(cose: &[u8]) -> bool {
        let Ok(Value::Tag(COSE_SIGN1_TAG, inner)) = ciborium::from_reader::<Value, _>(cose) else { return false };
        let Some(Value::Bytes(protected)) = inner.as_array().and_then(|f| f.first()) else { return false };
        let Ok(Value::Map(header)) = ciborium::from_reader::<Value, _>(protected.as_slice()) else { return false };
        map_get(&header, &Value::Integer(1.into())) == Some(&Value::Integer(ZK_ALG.into()))
            && map_get(&header, &text(CRIT_LABEL))
                .and_then(Value::as_map)
                .and_then(|ext| map_get(ext, &text("statement")))
                == Some(&text(STATEMENT))
    }

    /// Parse a third-party ZK signature; fails for any other `COSE_Sign1`.
    pub fn decode(cose: &[u8]) -> Result<Self> {
        let value = single_item(cose)?;
        let Value::Tag(COSE_SIGN1_TAG, inner) = value else {
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
        let Value::Map(header) = single_item(&protected)? else {
            bail!("protected header is not a map");
        };
        only_keys(&header, &[Value::Integer(1.into()), Value::Integer(2.into()), Value::Integer(33.into()), text(CRIT_LABEL)], "protected header")?;
        only_keys(&unprotected, &[text(TIME_STAMP_LABEL), text("pad"), text("pad2")], "unprotected header")?;
        for pad in ["pad", "pad2"] {
            match map_get(&unprotected, &text(pad)) {
                None => {}
                Some(Value::Bytes(b)) if b.iter().all(|&x| x == 0) => {}
                Some(_) => bail!("{pad} is not a byte string of zeros"),
            }
        }
        if map_get(&header, &Value::Integer(1.into())) != Some(&Value::Integer(ZK_ALG.into())) {
            bail!("not a ZK signature (alg is not {ZK_ALG})");
        }
        if map_get(&header, &Value::Integer(2.into())) != Some(&Value::Array(vec![text(CRIT_LABEL)])) {
            bail!("the ZK extension is not marked critical");
        }
        let ext = map_get(&header, &text(CRIT_LABEL)).and_then(Value::as_map).ok_or_else(|| anyhow!("no ZK extension"))?;
        only_keys(ext, &[text("statement"), text("vk"), text("curve")], "ZK extension")?;
        let curve = match map_get(ext, &text("curve")) {
            None => DEFAULT_CURVE.to_string(),
            Some(Value::Text(c)) if c != DEFAULT_CURVE => c.clone(),
            Some(_) => bail!("malformed curve field (BN254 is written by omission)"),
        };
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
        let time_stamp = map_get(&unprotected, &text(TIME_STAMP_LABEL)).and_then(Value::as_map).ok_or_else(|| anyhow!("no time stamp"))?;
        only_keys(time_stamp, &[text("tstTokens")], "time-stamp header")?;
        let tokens = map_get(time_stamp, &text("tstTokens"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("no time stamp"))?;
        let [token] = tokens.as_slice() else {
            bail!("the time-stamp header must hold exactly one token");
        };
        let token = token.as_map().ok_or_else(|| anyhow!("malformed time-stamp token"))?;
        only_keys(token, &[text("val")], "time-stamp token")?;
        let time_stamp_token = map_get(token, &text("val"))
            .and_then(Value::as_bytes)
            .cloned()
            .ok_or_else(|| anyhow!("time-stamp token has no val"))?;
        let (&version, proof) = signature.split_first().ok_or_else(|| anyhow!("empty signature"))?;
        if version != FORMAT_VERSION {
            bail!("unsupported ZK signature format version {version}");
        }
        let expected = proof_len(&curve)?;
        if proof.len() != expected {
            bail!("the proof is {} bytes; format version {FORMAT_VERSION} on {curve} has {expected}", proof.len());
        }
        Ok(Self { issuing_chain, vk_sha256, curve, time_stamp_token, proof: proof.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ZkSignature {
        ZkSignature {
            issuing_chain: vec![vec![0x30; 733]],
            vk_sha256: "ab".repeat(32),
            curve: DEFAULT_CURVE.into(),
            time_stamp_token: vec![0x30; 2000],
            proof: vec![7; proof_len(DEFAULT_CURVE).unwrap()],
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

    /// Re-encode a signature's CBOR with a change, for the strictness tests.
    fn tweak(z: &ZkSignature, f: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
        let Value::Tag(_, inner) = ciborium::from_reader::<Value, _>(z.encode(0, 0).as_slice()).unwrap() else { unreachable!() };
        let Value::Array(mut fields) = *inner else { unreachable!() };
        f(&mut fields);
        cbor(&Value::Tag(COSE_SIGN1_TAG, Box::new(Value::Array(fields))))
    }

    /// The format leaves no room for other data: a truncated or extended
    /// proof (an appended certificate, say), bytes after the item, non-zero
    /// padding, and unknown or duplicate header fields are all rejected.
    #[test]
    fn decode_is_strict() {
        let z = sample();
        let certificate = vec![0x30, 0x82, 0x02, 0x00];
        let len = proof_len(DEFAULT_CURVE).unwrap();
        for proof in [vec![7; len - 1], [vec![7; len], certificate.clone()].concat(), vec![]] {
            let other = ZkSignature { proof, ..z.clone() };
            assert!(ZkSignature::decode(&other.encode(0, 0)).is_err());
        }
        let trailing = [z.encode(0, 0), certificate].concat();
        assert!(ZkSignature::decode(&trailing).is_err());

        let unprotected = |f: fn(&mut Vec<(Value, Value)>)| {
            tweak(&z, |fields| {
                let Value::Map(m) = &mut fields[1] else { unreachable!() };
                f(m)
            })
        };
        let nonzero_pad = unprotected(|m| m.iter_mut().filter(|(k, _)| k == &text("pad")).for_each(|(_, v)| *v = Value::Bytes(vec![1, 2, 3])));
        let extra = unprotected(|m| m.push((text("x5chain"), Value::Bytes(vec![0x30]))));
        let duplicate = unprotected(|m| m.push((text("pad"), Value::Bytes(vec![]))));
        let extra_protected = tweak(&z, |fields| {
            let Value::Bytes(p) = &fields[0] else { unreachable!() };
            let Value::Map(mut m) = ciborium::from_reader::<Value, _>(p.as_slice()).unwrap() else { unreachable!() };
            m.push((Value::Integer(4.into()), Value::Bytes(vec![1])));
            fields[0] = Value::Bytes(cbor(&Value::Map(m)));
        });
        for (name, bytes) in [("non-zero pad", nonzero_pad), ("extra field", extra), ("duplicate field", duplicate), ("extra protected field", extra_protected)] {
            assert!(ZkSignature::decode(&bytes).is_err(), "{name} accepted");
        }
        // The untouched re-encoding still decodes.
        assert!(ZkSignature::decode(&tweak(&z, |_| {})).is_ok());
    }

    /// BLS12-381 signatures (roadmap E7) carry their curve and its proof
    /// length; BN254 ones are encoded exactly as before, without the field.
    #[test]
    fn curve_field() {
        let bn = sample();
        assert!(!bn.encode(0, 0).windows(5).any(|w| w == b"curve"), "BN254 encodings must not change");
        let bls = ZkSignature { curve: "bls12-381".into(), proof: vec![7; proof_len("bls12-381").unwrap()], ..sample() };
        assert_eq!(proof_len("bls12-381").unwrap(), 292);
        assert_eq!(ZkSignature::decode(&bls.encode(3, 1)).unwrap(), bls);
        // A BLS12-381 signature with a BN254-sized proof, and the reverse, are rejected.
        assert!(ZkSignature::decode(&ZkSignature { proof: vec![7; 196], ..bls.clone() }.encode(0, 0)).is_err());
        assert!(ZkSignature::decode(&ZkSignature { proof: vec![7; 292], ..bn.clone() }.encode(0, 0)).is_err());
        // BN254 is written by omission only; an explicit "bn254", or an unknown curve, is rejected.
        for curve in ["bn254", "secp256k1"] {
            let with = tweak(&bn, |fields| {
                let Value::Bytes(p) = &fields[0] else { unreachable!() };
                let Value::Map(mut m) = ciborium::from_reader::<Value, _>(p.as_slice()).unwrap() else { unreachable!() };
                for (k, v) in m.iter_mut() {
                    if k == &text(CRIT_LABEL) {
                        let Value::Map(ext) = v else { unreachable!() };
                        ext.push((text("curve"), text(curve)));
                    }
                }
                fields[0] = Value::Bytes(cbor(&Value::Map(m)));
            });
            assert!(ZkSignature::decode(&with).is_err(), "{curve} accepted");
        }
    }

    #[test]
    fn decode_rejects_other_signatures() {
        let z = sample();
        let good = z.encode(0, 0);
        assert!(ZkSignature::decode(&good[1..]).is_err());
        let wrong_version = tweak(&z, |fields| {
            let Value::Bytes(sig) = &mut fields[3] else { unreachable!() };
            sig[0] = 9;
        });
        assert!(ZkSignature::decode(&wrong_version).is_err());
        let mut empty_chain = z;
        empty_chain.issuing_chain.clear();
        assert!(ZkSignature::decode(&empty_chain.encode(0, 0)).is_err());
    }
}
