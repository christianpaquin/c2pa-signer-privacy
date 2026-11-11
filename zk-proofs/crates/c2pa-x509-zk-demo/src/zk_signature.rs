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
//! With the issuer hidden (roadmap H4, HIDING-THE-ISSUER.md, I5): no
//! `x5chain`; the statement is "third-party-hidden-issuer/1", and the ZK
//! extension adds "issuers": {"format": the tree format, "root": the issuer
//! tree's root (canonical lowercase hex), "list": the anonymizer's name for
//! the trust-list snapshot, a hint the verifier never trusts}.
//!
//! With the issuer and the time stamp hidden (roadmap I6,
//! HIDING-THE-TIME-STAMP.md, T6): no `x5chain` and no time-stamp token (the
//! unprotected header holds only the padding); the statement is
//! "third-party-hidden/1", and the ZK extension holds "issuers" as above,
//! "tsa": the TSA tree, in the same form, and "window": [t1, t2], the
//! half-open window of Unix seconds the token's time lies in, aligned (t1 a
//! multiple of t2 - t1) and below 2^34.
//!
//! Decoding is strict, so the format leaves no room for other data (a signer
//! certificate, say): exactly one CBOR item, exactly these header fields,
//! all-zero padding, and a proof of exactly its curve's length (`proof_len`).

use anyhow::{anyhow, bail, Result};
use ciborium::Value;

pub const ZK_ALG: i64 = -65538;
pub const CRIT_LABEL: &str = "c2pa-x509-zk";
pub const STATEMENT: &str = "third-party/1";
pub const STATEMENT_HIDDEN_ISSUER: &str = "third-party-hidden-issuer/1";
pub const STATEMENT_HIDDEN_ALL: &str = "third-party-hidden/1";
/// The window's endpoints are below 2^WINDOW_BITS (the circuit's bound).
pub const WINDOW_BITS: u32 = 34;

/// Whether [t1, t2) is a window the format accepts: non-empty, below
/// 2^WINDOW_BITS, and aligned (t1 a multiple of its length).
pub fn is_aligned_window(t1: u64, t2: u64) -> bool {
    t1 < t2 && t2 < (1 << WINDOW_BITS) && t1 % (t2 - t1) == 0
}
/// The issuer tree format the hidden-issuer statement uses (gnark/issuertree).
pub const ISSUER_TREE_FORMAT: u64 = 1;
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

/// The issuer tree a hidden-issuer proof is made against.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuerTreeRef {
    /// The tree's root, canonical lowercase hex.
    pub root: String,
    /// The anonymizer's name for the trust-list snapshot: a hint only.
    pub list: String,
}

/// Whether `root` is canonical lowercase hex: no prefix, no leading zeros.
pub fn is_canonical_root(root: &str) -> bool {
    root == "0" || (!root.is_empty() && !root.starts_with('0') && root.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// The third-party ZK signature's contents.
#[derive(Debug, Clone, PartialEq)]
pub struct ZkSignature {
    /// The issuing CA chain, issuing CA first; empty when the issuer is hidden.
    pub issuing_chain: Vec<Vec<u8>>,
    /// The issuer tree, when the issuer is hidden (H4).
    pub issuers: Option<IssuerTreeRef>,
    /// The TSA tree, when the time stamp is hidden too (I6).
    pub tsa: Option<IssuerTreeRef>,
    /// The window [t1, t2) of the hidden time stamp (I6).
    pub window: Option<(u64, u64)>,
    /// SHA-256 of the verifying key (hex), identifying the circuit and keys.
    pub vk_sha256: String,
    /// The proof system's curve ("bn254" or "bls12-381"; roadmap E7).
    pub curve: String,
    /// The original RFC 3161 time-stamp token (`sigTst2`); empty when hidden.
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
        self.encode_with_chain(&self.issuing_chain, pad, pad2)
    }

    fn encode_with_chain(&self, chain: &[Vec<u8>], pad: usize, pad2: usize) -> Vec<u8> {
        let statement = match (&self.issuers, &self.tsa) {
            (_, Some(_)) => STATEMENT_HIDDEN_ALL,
            (Some(_), None) => STATEMENT_HIDDEN_ISSUER,
            (None, None) => STATEMENT,
        };
        let tree = |t: &IssuerTreeRef| {
            Value::Map(vec![
                (text("format"), Value::Integer(ISSUER_TREE_FORMAT.into())),
                (text("root"), text(&t.root)),
                (text("list"), text(&t.list)),
            ])
        };
        let mut ext = vec![(text("statement"), text(statement)), (text("vk"), text(&self.vk_sha256))];
        // Written only for other curves, so BN254 signatures are unchanged.
        if self.curve != DEFAULT_CURVE {
            ext.push((text("curve"), text(&self.curve)));
        }
        if let Some(issuers) = &self.issuers {
            ext.push((text("issuers"), tree(issuers)));
        }
        if let Some(tsa) = &self.tsa {
            ext.push((text("tsa"), tree(tsa)));
        }
        if let Some((t1, t2)) = self.window {
            ext.push((text("window"), Value::Array(vec![Value::Integer(t1.into()), Value::Integer(t2.into())])));
        }
        let mut protected = vec![
            (Value::Integer(1.into()), Value::Integer(ZK_ALG.into())),
            (Value::Integer(2.into()), Value::Array(vec![text(CRIT_LABEL)])),
        ];
        if !chain.is_empty() {
            protected.push((Value::Integer(33.into()), Value::Array(chain.iter().cloned().map(Value::Bytes).collect())));
        }
        protected.push((text(CRIT_LABEL), Value::Map(ext)));
        let protected = Value::Map(protected);
        let time_stamp = Value::Map(vec![(
            text("tstTokens"),
            Value::Array(vec![Value::Map(vec![(text("val"), Value::Bytes(self.time_stamp_token.clone()))])]),
        )]);
        let mut unprotected = Vec::new();
        if self.tsa.is_none() {
            unprotected.push((text(TIME_STAMP_LABEL), time_stamp));
        }
        unprotected.push((text("pad"), Value::Bytes(vec![0; pad])));
        unprotected.push((text("pad2"), Value::Bytes(vec![0; pad2])));
        let unprotected = Value::Map(unprotected);
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
        self.encode_exact_with_chain(&self.issuing_chain, size)
    }

    /// For validating a hidden-issuer asset's claim with c2pa (I5): this
    /// signature with `x5chain` holding `placeholder` instead of nothing, at
    /// exactly `size` bytes. c2pa-rs does not read a manifest whose signature
    /// has no `x5chain`; the placeholder identifies no one, and is never
    /// written to an output.
    pub fn encode_for_validation(&self, placeholder: &[u8], size: usize) -> Result<Vec<u8>> {
        self.encode_exact_with_chain(&[placeholder.to_vec()], size)
    }

    fn encode_exact_with_chain(&self, chain: &[Vec<u8>], size: usize) -> Result<Vec<u8>> {
        let unpadded = self.encode_with_chain(chain, 0, 0).len();
        let Some(room) = size.checked_sub(unpadded) else {
            bail!("the ZK signature needs {unpadded} bytes, but the original signature has only {size}");
        };
        for pad2 in 0..=32 {
            // A pad of n bytes adds n plus its length header (0, 1, or 2 bytes
            // beyond the empty one), so the right length is just below the room.
            for pad in (room.saturating_sub(pad2 + 4)..=room).rev() {
                let encoded = self.encode_with_chain(chain, pad, pad2);
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
                .is_some_and(|s| *s == text(STATEMENT) || *s == text(STATEMENT_HIDDEN_ISSUER) || *s == text(STATEMENT_HIDDEN_ALL))
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
        only_keys(ext, &[text("statement"), text("vk"), text("curve"), text("issuers"), text("tsa"), text("window")], "ZK extension")?;
        let curve = match map_get(ext, &text("curve")) {
            None => DEFAULT_CURVE.to_string(),
            Some(Value::Text(c)) if c != DEFAULT_CURVE => c.clone(),
            Some(_) => bail!("malformed curve field (BN254 is written by omission)"),
        };
        // The statement fixes the form: (issuer hidden, time stamp hidden).
        let (hidden, hidden_time_stamp) = match map_get(ext, &text("statement")) {
            Some(s) if *s == text(STATEMENT) => (false, false),
            Some(s) if *s == text(STATEMENT_HIDDEN_ISSUER) => (true, false),
            Some(s) if *s == text(STATEMENT_HIDDEN_ALL) => (true, true),
            _ => bail!("not a third-party ZK signature (statement is not {STATEMENT}, {STATEMENT_HIDDEN_ISSUER}, or {STATEMENT_HIDDEN_ALL})"),
        };
        let tree_ref = |value: &Value, what: &str| -> Result<IssuerTreeRef> {
            let map = value.as_map().ok_or_else(|| anyhow!("{what} is not a map"))?;
            only_keys(map, &[text("format"), text("root"), text("list")], what)?;
            if map_get(map, &text("format")) != Some(&Value::Integer(ISSUER_TREE_FORMAT.into())) {
                bail!("unsupported {what} tree format (expected {ISSUER_TREE_FORMAT})");
            }
            let root = map_get(map, &text("root")).and_then(Value::as_text).ok_or_else(|| anyhow!("no {what} tree root"))?;
            if !is_canonical_root(root) {
                bail!("the {what} tree root is not canonical lowercase hex");
            }
            let list = map_get(map, &text("list")).and_then(Value::as_text).ok_or_else(|| anyhow!("no {what} trust-list name"))?;
            Ok(IssuerTreeRef { root: root.to_string(), list: list.to_string() })
        };
        let issuers = match (hidden, map_get(ext, &text("issuers"))) {
            (false, None) => None,
            (false, Some(_)) => bail!("issuers given for the disclosed statement"),
            (true, None) => bail!("no issuers for a hidden-issuer statement"),
            (true, Some(value)) => Some(tree_ref(value, "issuers")?),
        };
        let tsa = match (hidden_time_stamp, map_get(ext, &text("tsa"))) {
            (false, None) => None,
            (false, Some(_)) => bail!("a TSA tree given for a statement with a disclosed time stamp"),
            (true, None) => bail!("no TSA tree for the hidden-time-stamp statement"),
            (true, Some(value)) => Some(tree_ref(value, "tsa")?),
        };
        let window = match (hidden_time_stamp, map_get(ext, &text("window"))) {
            (false, None) => None,
            (false, Some(_)) => bail!("a window given for a statement with a disclosed time stamp"),
            (true, None) => bail!("no window for the hidden-time-stamp statement"),
            (true, Some(value)) => {
                let bounds = value.as_array().ok_or_else(|| anyhow!("the window is not an array"))?;
                let [Value::Integer(t1), Value::Integer(t2)] = bounds.as_slice() else {
                    bail!("the window is not two integers");
                };
                let (t1, t2) = (u64::try_from(*t1).map_err(|_| anyhow!("the window's start is not a Unix time"))?, u64::try_from(*t2).map_err(|_| anyhow!("the window's end is not a Unix time"))?);
                if !is_aligned_window(t1, t2) {
                    bail!("the window [{t1}, {t2}) is not an aligned window of Unix seconds below 2^{WINDOW_BITS}");
                }
                Some((t1, t2))
            }
        };
        let vk_sha256 = map_get(ext, &text("vk")).and_then(Value::as_text).ok_or_else(|| anyhow!("no verifying-key hash"))?.to_string();
        let x5chain = map_get(&header, &Value::Integer(33.into()));
        let issuing_chain = match (hidden, x5chain) {
            (true, Some(_)) => bail!("an x5chain in a hidden-issuer signature"),
            (true, None) => Vec::new(),
            (false, None) => bail!("no x5chain"),
            (false, Some(chain)) => {
                let chain = chain
                    .as_array()
                    .ok_or_else(|| anyhow!("x5chain is not an array"))?
                    .iter()
                    .map(|c| c.as_bytes().cloned().ok_or_else(|| anyhow!("x5chain entry is not a byte string")))
                    .collect::<Result<Vec<_>>>()?;
                if chain.is_empty() {
                    bail!("x5chain is empty");
                }
                chain
            }
        };
        let time_stamp_token = match (hidden_time_stamp, map_get(&unprotected, &text(TIME_STAMP_LABEL))) {
            (true, Some(_)) => bail!("a time-stamp token in a hidden-time-stamp signature"),
            (true, None) => Vec::new(),
            (false, None) => bail!("no time stamp"),
            (false, Some(time_stamp)) => {
                let time_stamp = time_stamp.as_map().ok_or_else(|| anyhow!("no time stamp"))?;
                only_keys(time_stamp, &[text("tstTokens")], "time-stamp header")?;
                let tokens = map_get(time_stamp, &text("tstTokens"))
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("no time stamp"))?;
                let [token] = tokens.as_slice() else {
                    bail!("the time-stamp header must hold exactly one token");
                };
                let token = token.as_map().ok_or_else(|| anyhow!("malformed time-stamp token"))?;
                only_keys(token, &[text("val")], "time-stamp token")?;
                map_get(token, &text("val"))
                    .and_then(Value::as_bytes)
                    .cloned()
                    .ok_or_else(|| anyhow!("time-stamp token has no val"))?
            }
        };
        let (&version, proof) = signature.split_first().ok_or_else(|| anyhow!("empty signature"))?;
        if version != FORMAT_VERSION {
            bail!("unsupported ZK signature format version {version}");
        }
        let expected = proof_len(&curve)?;
        if proof.len() != expected {
            bail!("the proof is {} bytes; format version {FORMAT_VERSION} on {curve} has {expected}", proof.len());
        }
        Ok(Self { issuing_chain, issuers, tsa, window, vk_sha256, curve, time_stamp_token, proof: proof.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ZkSignature {
        ZkSignature {
            issuing_chain: vec![vec![0x30; 733]],
            issuers: None,
            tsa: None,
            window: None,
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

    fn hidden() -> ZkSignature {
        ZkSignature {
            issuing_chain: vec![],
            issuers: Some(IssuerTreeRef { root: "1a2b3c".into(), list: "c2pa-official@a95f2c4".into() }),
            ..sample()
        }
    }

    /// Re-encode `cose` with its protected header changed by `f`.
    fn with_header(cose: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        let Value::Tag(tag, inner) = single_item(cose).unwrap() else { panic!() };
        let Value::Array(mut fields) = *inner else { panic!() };
        let Value::Bytes(p) = &fields[0] else { panic!() };
        let Value::Map(mut header) = single_item(p).unwrap() else { panic!() };
        f(&mut header);
        fields[0] = Value::Bytes(cbor(&Value::Map(header)));
        cbor(&Value::Tag(tag, Box::new(Value::Array(fields))))
    }

    fn with_ext(cose: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        with_header(cose, |header| {
            let (_, Value::Map(ext)) = header.iter_mut().find(|(k, _)| *k == text(CRIT_LABEL)).unwrap() else { panic!() };
            f(ext);
        })
    }

    fn with_issuers(cose: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        with_ext(cose, |ext| {
            let (_, Value::Map(issuers)) = ext.iter_mut().find(|(k, _)| *k == text("issuers")).unwrap() else { panic!() };
            f(issuers);
        })
    }

    #[test]
    fn hidden_issuer_round_trips_without_x5chain() {
        let z = hidden();
        let cose = z.encode(4, 1);
        assert!(ZkSignature::is_declared(&cose));
        assert_eq!(ZkSignature::decode(&cose).unwrap(), z);
        let Value::Tag(_, inner) = single_item(&cose).unwrap() else { panic!() };
        let Value::Bytes(p) = &inner.as_array().unwrap()[0] else { panic!() };
        assert!(map_get(single_item(p).unwrap().as_map().unwrap(), &Value::Integer(33.into())).is_none(), "x5chain written");
        // The hidden form is shorter than the disclosed one by the chain.
        assert!(z.encode(0, 0).len() + 600 < sample().encode(0, 0).len()); // the 733-byte chain, less the tree reference
    }

    #[test]
    fn hidden_and_disclosed_forms_do_not_mix() {
        let hidden = hidden().encode(0, 0);
        let disclosed = sample().encode(0, 0);
        let chain = Value::Array(vec![Value::Bytes(vec![0x30; 10])]);
        for (name, cose) in [
            ("an x5chain in the hidden form", with_header(&hidden, |h| h.insert(2, (Value::Integer(33.into()), chain.clone())))),
            ("no issuers in the hidden form", with_ext(&hidden, |e| e.retain(|(k, _)| *k != text("issuers")))),
            ("issuers in the disclosed form", with_ext(&disclosed, |e| e.push((text("issuers"), Value::Map(vec![]))))),
            ("no x5chain in the disclosed form", with_header(&disclosed, |h| h.retain(|(k, _)| *k != Value::Integer(33.into())))),
            ("another tree format", with_issuers(&hidden, |i| i[0].1 = Value::Integer(2.into()))),
            ("an unexpected issuers field", with_issuers(&hidden, |i| i.push((text("ca"), text("x"))))),
            ("no root", with_issuers(&hidden, |i| i.retain(|(k, _)| *k != text("root")))),
            ("no list", with_issuers(&hidden, |i| i.retain(|(k, _)| *k != text("list")))),
        ] {
            assert!(ZkSignature::decode(&cose).is_err(), "{name}: accepted");
        }
    }

    #[test]
    fn issuer_roots_have_one_form() {
        for good in ["0", "1", "1a2b3c", "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"] {
            assert!(is_canonical_root(good), "{good}");
            let cose = with_issuers(&hidden().encode(0, 0), |i| i[1].1 = text(good));
            assert!(ZkSignature::decode(&cose).is_ok(), "{good}");
        }
        for bad in ["", "01a", "1A2B", "0x1a", "-1", "1a 2b", "g1"] {
            assert!(!is_canonical_root(bad), "{bad}");
            let cose = with_issuers(&hidden().encode(0, 0), |i| i[1].1 = text(bad));
            assert!(ZkSignature::decode(&cose).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn validation_copy_carries_the_placeholder_at_the_same_size() {
        let z = hidden();
        let size = sample().encode(50, 0).len();
        let copy = z.encode_for_validation(&[0x30; 400], size).unwrap();
        assert_eq!(copy.len(), size);
        // Not a valid hidden-issuer signature (it has an x5chain): it is only
        // ever given to c2pa, never written to an output.
        assert!(ZkSignature::decode(&copy).is_err());
        assert_eq!(z.encode_exact(size).unwrap().len(), size);
    }

    fn hidden_all() -> ZkSignature {
        ZkSignature {
            tsa: Some(IssuerTreeRef { root: "4d5e6f".into(), list: "c2pa-tsa@a95f2c4".into() }),
            window: Some((1_794_355_200, 1_794_441_600)), // 2026-11-11, a UTC day
            time_stamp_token: Vec::new(),
            ..hidden()
        }
    }

    /// Re-encode `cose` with its unprotected header changed by `f`.
    fn with_unprotected(cose: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        let Value::Tag(tag, inner) = single_item(cose).unwrap() else { panic!() };
        let Value::Array(mut fields) = *inner else { panic!() };
        let Value::Map(mut unprotected) = fields[1].clone() else { panic!() };
        f(&mut unprotected);
        fields[1] = Value::Map(unprotected);
        cbor(&Value::Tag(tag, Box::new(Value::Array(fields))))
    }

    #[test]
    fn hidden_all_round_trips_without_x5chain_or_token() {
        let z = hidden_all();
        let cose = z.encode(4, 1);
        assert!(ZkSignature::is_declared(&cose));
        assert_eq!(ZkSignature::decode(&cose).unwrap(), z);
        let Value::Tag(_, inner) = single_item(&cose).unwrap() else { panic!() };
        let unprotected = inner.as_array().unwrap()[1].as_map().unwrap().clone();
        assert!(map_get(&unprotected, &text(TIME_STAMP_LABEL)).is_none(), "time-stamp label written");
        // The token's space becomes padding: shorter than the hidden-issuer form by the token.
        assert!(z.encode(0, 0).len() + 1900 < hidden().encode(0, 0).len());
    }

    #[test]
    fn hidden_all_form_does_not_mix() {
        let all = hidden_all().encode(0, 0);
        let issuer_only = hidden().encode(0, 0);
        let token = Value::Map(vec![(text("tstTokens"), Value::Array(vec![Value::Map(vec![(text("val"), Value::Bytes(vec![0x30; 10]))])]))]);
        let tree = Value::Map(vec![(text("format"), Value::Integer(1.into())), (text("root"), text("1")), (text("list"), text("x"))]);
        for (name, cose) in [
            ("a token in the hidden-all form", with_unprotected(&all, |u| u.insert(0, (text(TIME_STAMP_LABEL), token.clone())))),
            ("an x5chain in the hidden-all form", with_header(&all, |h| h.insert(2, (Value::Integer(33.into()), Value::Array(vec![Value::Bytes(vec![0x30; 10])]))))),
            ("no TSA tree", with_ext(&all, |e| e.retain(|(k, _)| *k != text("tsa")))),
            ("no window", with_ext(&all, |e| e.retain(|(k, _)| *k != text("window")))),
            ("no issuers", with_ext(&all, |e| e.retain(|(k, _)| *k != text("issuers")))),
            ("a TSA tree in the hidden-issuer form", with_ext(&issuer_only, |e| e.push((text("tsa"), tree.clone())))),
            ("a window in the hidden-issuer form", with_ext(&issuer_only, |e| e.push((text("window"), Value::Array(vec![Value::Integer(0.into()), Value::Integer(1.into())]))))),
        ] {
            assert!(ZkSignature::decode(&cose).is_err(), "{name}: accepted");
        }
    }

    #[test]
    fn windows_are_aligned_and_bounded() {
        let day = 86_400u64;
        let t = 1_794_355_200u64; // a UTC midnight
        for (t1, t2, ok) in [
            (t, t + day, true),
            (t + 3600, t + 7200, true),         // an hour
            (t + 5, t + 6, true),               // a second
            (t + 1, t + day + 1, false),        // a day, not aligned
            (t, t, false),                      // empty
            (t + day, t, false),                // reversed
            (0, 1 << WINDOW_BITS, false),       // beyond 2^34
        ] {
            assert_eq!(is_aligned_window(t1, t2), ok, "[{t1}, {t2})");
            let cose = with_ext(&hidden_all().encode(0, 0), |e| {
                let (_, w) = e.iter_mut().find(|(k, _)| *k == text("window")).unwrap();
                *w = Value::Array(vec![Value::Integer(t1.into()), Value::Integer(t2.into())]);
            });
            assert_eq!(ZkSignature::decode(&cose).is_ok(), ok, "[{t1}, {t2}) in a signature");
        }
    }
}
