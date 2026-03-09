//! Circuit interface for ZK proof generation and verification
//!
//! This module provides the interface between Rust and the Circom/snarkjs
//! proving system. It generates witness JSON and invokes snarkjs for proving.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

/// Circuit parameters for P-256: n=43 bits, k=6 registers
const N_BITS: usize = 43;
const K_REGISTERS: usize = 6;
const MAX_CERT_BYTES: usize = 1500;

/// Inputs to the ZK circuit in the format expected by snarkjs / ark-circom.
///
/// Field names use camelCase to match the Circom signal names exactly.
/// Public inputs: caPubKeyX, caPubKeyY, claimHash, photoTimestamp.
/// Private inputs (witness): all others.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitInputs {
    // --- Public inputs ---
    /// Trusted CA's P-256 public key X coordinate as k n-bit registers (public)
    pub ca_pub_key_x: [String; K_REGISTERS],
    /// Trusted CA's P-256 public key Y coordinate as k n-bit registers (public)
    pub ca_pub_key_y: [String; K_REGISTERS],
    /// C2PA claim hash as k registers of n bits (public)
    pub claim_hash: [String; K_REGISTERS],
    /// Unix timestamp of when the asset was anonymized (public, decimal string)
    pub photo_timestamp: String,

    // --- Private inputs (witness) ---
    /// DER-encoded certificate bytes, zero-padded to MAX_CERT_BYTES (private)
    pub cert_der: Vec<String>,
    /// Actual byte length of certDer (private, decimal string)
    pub cert_len: String,
    /// CA's ECDSA signature r over TBSCertificate (private)
    pub cert_sig_r: [String; K_REGISTERS],
    /// CA's ECDSA signature s over TBSCertificate (private)
    pub cert_sig_s: [String; K_REGISTERS],
    /// Signer's ECDSA signature r over claimHash (private)
    pub claim_sig_r: [String; K_REGISTERS],
    /// Signer's ECDSA signature s over claimHash (private)
    pub claim_sig_s: [String; K_REGISTERS],
    // --- Private inputs — DER structural hints (verified by X509Parse) ---
    /// Byte offset of the TBSCertificate SEQUENCE tag within certDer (private)
    pub tbs_offset: String,
    /// Declared byte-length value from the TBS DER header (private)
    pub tbs_len: String,
    /// Byte offset of the 32-byte X coordinate in the SPKI EC point (private)
    pub spki_x_offset: String,
    /// Byte offset of the notBefore UTCTime tag (0x17) within certDer (private)
    pub not_before_offset: String,
    /// Byte offset of the notAfter UTCTime tag (0x17) within certDer (private)
    pub not_after_offset: String,
    /// SHA-256 padded byte length of the TBS slice (multiple of 64, private)
    pub tbs_hash_padded_len: String,

    // --- Private inputs — SHA-256-padded TBS bytes (for in-circuit hash) ---
    /// TBS bytes with SHA-256 padding appended, zero-padded to 1536 bytes.
    /// The circuit runs Sha256Bytes(1536) over this buffer in-circuit.
    /// Each entry is a decimal string (byte value 0–255).
    /// Length must equal MAX_TBS_PADDED (1536).
    #[serde(rename = "tbsHashPaddedBytes")]
    pub tbs_padded_bytes: Vec<String>,
}

/// Inputs to the ZK circuit (Rust-native format before conversion)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofInputs {
    /// DER-encoded leaf certificate (private)
    pub cert_der: Vec<u8>,
    /// ECDSA signature over claim_hash using leaf private key (private)
    pub sig_over_claim: SignatureComponents,
    /// C2PA claim hash — 32 bytes (public)
    pub claim_hash: Vec<u8>,
    /// Trusted CA public key (public)
    pub ca_pubkey: PublicKeyComponents,
    /// Unix timestamp when the asset was anonymized (public)
    pub photo_timestamp: u64,
}

/// Public outputs from the ZK circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOutputs {
    /// Canonical issuer DN extracted from certificate
    pub issuer: String,
    /// Claim hash (echoed from input for binding)
    pub claim_hash: Vec<u8>,
}

/// ECDSA signature components (r, s) as big integers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureComponents {
    /// r component as hex string (32 bytes)
    pub r: String,
    /// s component as hex string (32 bytes)  
    pub s: String,
}

/// ECDSA public key components (x, y) for P-256
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyComponents {
    /// x coordinate as hex string (32 bytes)
    pub x: String,
    /// y coordinate as hex string (32 bytes)
    pub y: String,
}

/// A SNARK proof with its public signals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkProof {
    /// The proof data (Groth16: pi_a, pi_b, pi_c)
    pub proof: ProofData,
    /// Public signals from the circuit
    pub public_signals: Vec<String>,
}

/// Groth16 proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
    pub curve: String,
}

impl SnarkProof {
    /// Serialize to base64 for embedding in manifests
    pub fn to_base64(&self) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&json))
    }
    
    /// Deserialize from base64
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

use base64::Engine;

/// Path to Circom build artifacts
pub struct CircuitPaths {
    pub circuit_wasm: std::path::PathBuf,
    pub proving_key: std::path::PathBuf,
    pub verification_key: std::path::PathBuf,
}

impl CircuitPaths {
    /// Default paths relative to the circuits directory
    pub fn default_for_circuit(circuits_dir: &Path, circuit_name: &str) -> Self {
        let build_dir = circuits_dir.join("build");
        Self {
            circuit_wasm: build_dir.join(format!("{circuit_name}_js/{circuit_name}.wasm")),
            proving_key: build_dir.join(format!("{circuit_name}.zkey")),
            verification_key: build_dir.join("verification_key.json"),
        }
    }
}

/// Find the byte offset of the TBSCertificate SEQUENCE within a DER certificate.
///
/// A Certificate is: SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING }
/// The TBSCertificate starts immediately after the outer SEQUENCE tag + length bytes.
fn compute_tbs_offset(cert_der: &[u8]) -> Result<usize> {
    if cert_der.len() < 4 || cert_der[0] != 0x30 {
        anyhow::bail!("certificate is not a DER SEQUENCE (got 0x{:02x})", cert_der.first().unwrap_or(&0));
    }
    let tbs_start = match cert_der[1] {
        0x82 => 4usize,  // 0x82 HH LL: 3 length bytes + 1 tag byte
        0x81 => 3usize,  // 0x81 LL:    2 length bytes + 1 tag byte
        b if b <= 0x7f => 2usize,  // 1-byte length + 1 tag byte
        b => anyhow::bail!("unsupported outer SEQUENCE length form: 0x{:02x}", b),
    };
    if cert_der.get(tbs_start) != Some(&0x30) {
        anyhow::bail!(
            "expected TBSCertificate SEQUENCE (0x30) at offset {}, got 0x{:02x}",
            tbs_start,
            cert_der.get(tbs_start).unwrap_or(&0)
        );
    }
    Ok(tbs_start)
}

/// Parse the declared byte length of TBSCertificate from its DER header.
fn compute_tbs_len(cert_der: &[u8], tbs_offset: usize) -> Result<usize> {
    let len_byte = cert_der.get(tbs_offset + 1).copied()
        .ok_or_else(|| anyhow!("certificate too short for TBS length byte"))?;
    let tbs_len = match len_byte {
        0x82 => {
            let msb = *cert_der.get(tbs_offset + 2)
                .ok_or_else(|| anyhow!("certificate too short for TBS length MSB"))? as usize;
            let lsb = *cert_der.get(tbs_offset + 3)
                .ok_or_else(|| anyhow!("certificate too short for TBS length LSB"))? as usize;
            msb * 256 + lsb
        }
        0x81 => {
            *cert_der.get(tbs_offset + 2)
                .ok_or_else(|| anyhow!("certificate too short for TBS length"))? as usize
        }
        b if b <= 0x7f => b as usize,
        b => anyhow::bail!("unsupported TBS length encoding: 0x{:02x}", b),
    };
    Ok(tbs_len)
}

/// Find `notBeforeOffset`: byte offset of the first UTCTime (0x17) tag inside
/// the Validity SEQUENCE of the TBSCertificate.
///
/// RFC 5280 §4.1.2.5 Validity = SEQUENCE { notBefore Time, notAfter Time }.
/// We search forward from `tbs_offset + 4` (skip TBS tag+len) for the first
/// 0x17 tag that is followed by length byte 0x0D (13, the fixed UTCTime length).
fn compute_not_before_offset(cert_der: &[u8], tbs_offset: usize) -> Result<usize> {
    // Start after the TBS DER header (tag 0x30, 0x82, HH, LL = 4 bytes).
    let search_start = tbs_offset + 4;
    for i in search_start..cert_der.len().saturating_sub(1) {
        if cert_der[i] == 0x17 && cert_der[i + 1] == 0x0D {
            return Ok(i);
        }
    }
    anyhow::bail!("notBefore UTCTime tag (0x17 0x0D) not found in TBSCertificate");
}

/// Find `notAfterOffset`: byte offset of the second UTCTime (0x17) tag after
/// the notBefore field.
fn compute_not_after_offset(cert_der: &[u8], not_before_offset: usize) -> Result<usize> {
    // Skip past the notBefore tag (0x17) + length (0x0D) + 13 content bytes = 15 bytes.
    let search_start = not_before_offset + 15;
    for i in search_start..cert_der.len().saturating_sub(1) {
        if cert_der[i] == 0x17 && cert_der[i + 1] == 0x0D {
            return Ok(i);
        }
    }
    anyhow::bail!("notAfter UTCTime tag (0x17 0x0D) not found after notBefore");
}

/// Build the SHA-256-padded TBS byte buffer consumed by Sha256Bytes(1536).
///
/// SHA-256 padding: append 0x80, then zero bytes, then the 8-byte big-endian
/// bit count, such that the total length is a multiple of 64.  We cap at 1536
/// bytes because that is the `maxTbsPadded` value in the Circom circuit.
///
/// Returns `(padded_bytes, padded_len)` where:
/// - `padded_bytes` is a 1536-element Vec of byte values (u8)
/// - `padded_len` is the first multiple of 64 that fits the TBS + SHA-256 padding
fn compute_tbs_sha256_padding(
    cert_der: &[u8],
    tbs_offset: usize,
    tbs_len: usize,
) -> Result<(Vec<u8>, usize)> {
    const MAX_TBS_PADDED: usize = 1536;

    // TBS DER region: tag(1) + 0x82(1) + HH(1) + LL(1) + content(tbs_len)
    let tbs_der_len = 4 + tbs_len;
    let tbs_end = tbs_offset + tbs_der_len;
    if tbs_end > cert_der.len() {
        anyhow::bail!(
            "TBS region {}..{} exceeds certificate length {}",
            tbs_offset, tbs_end, cert_der.len()
        );
    }
    let tbs_bytes = &cert_der[tbs_offset..tbs_end];

    // SHA-256 padding: message || 0x80 || zero_bytes || 8-byte-big-endian-bit-count
    // Total length must be a multiple of 64.
    let msg_bit_len = (tbs_der_len as u64) * 8;
    // +1 for 0x80, +8 for bit-length field
    let min_padded = tbs_der_len + 1 + 8;
    let padded_len = ((min_padded + 63) / 64) * 64;

    if padded_len > MAX_TBS_PADDED {
        anyhow::bail!(
            "TBS padded length {} exceeds maxTbsPadded {}",
            padded_len, MAX_TBS_PADDED
        );
    }

    let mut buf = vec![0u8; MAX_TBS_PADDED];
    buf[..tbs_der_len].copy_from_slice(tbs_bytes);
    buf[tbs_der_len] = 0x80;
    // Zero bytes are already in place.
    // Write 8-byte big-endian bit count at padded_len - 8.
    let bit_len_bytes = msg_bit_len.to_be_bytes();
    buf[padded_len - 8..padded_len].copy_from_slice(&bit_len_bytes);

    Ok((buf, padded_len))
}

/// Find the byte offset of the EC public key X coordinate within `cert_der`.
///
/// Searches for the uncompressed EC point marker byte (0x04) followed by the
/// known 32-byte X coordinate.  Returns the offset of the first X byte
/// (i.e., one past the 0x04 marker).
fn compute_spki_x_offset(cert_der: &[u8], x_bytes: &[u8; 32]) -> Result<usize> {
    // Build: [0x04, x[0], x[1], ..., x[31]]
    let mut needle = [0u8; 33];
    needle[0] = 0x04;
    needle[1..].copy_from_slice(x_bytes);
    cert_der
        .windows(33)
        .position(|w| w == needle)
        .map(|pos| pos + 1) // +1: X bytes start after the 0x04 marker
        .ok_or_else(|| anyhow!("EC public key X coordinate not found in certificate DER"))
}

/// Convert a 32-byte value to k registers of n bits (circom BigInt format).
///
/// Registers are least-significant first (LSB register 0, MSB register k-1).
/// This matches the internal encoding of `ECDSAVerifyNoPubkeyCheck` and is
/// used both to build circuit witnesses and to reconstruct expected public
/// input values from byte-level data (e.g. CA public key, claim hash) for
/// post-verification binding checks.
pub fn bytes_to_registers(bytes: &[u8; 32]) -> [String; K_REGISTERS] {
    use num_bigint::BigUint;

    let val = BigUint::from_bytes_be(bytes);
    let mask = (BigUint::from(1u64) << N_BITS) - 1u64;

    let mut result: [String; K_REGISTERS] = Default::default();
    let mut temp = val;
    for i in 0..K_REGISTERS {
        let limb = &temp & &mask;
        result[i] = limb.to_string();
        temp >>= N_BITS;
    }
    result
}

/// Extract the subject P-256 public key from a DER-encoded X.509 certificate
/// and return it as two k-register arrays in the cicom BigInt format used by
/// `ECDSAVerifyNoPubkeyCheck`.
///
/// Returns `(x_registers, y_registers)` where each array has `K_REGISTERS`
/// decimal-string limbs (LSB-first, n bits each).
///
/// Used by the verifier to reconstruct the expected `caPubKeyX/Y` public
/// signals from the trusted CA DER certificate, so it can confirm the proof's
/// embedded public inputs match the CA the operator actually trusts.
#[allow(deprecated)] // generic-array 0.x as_slice() — harmless until dependency upgrade
pub fn pubkey_registers_from_der(cert_der: &[u8]) -> Result<([String; K_REGISTERS], [String; K_REGISTERS])> {
    use der::Decode;
    use x509_cert::Certificate;
    use p256::PublicKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("failed to parse X.509 certificate: {e}"))?;

    let pk_bytes = cert.tbs_certificate.subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("public key not byte-aligned"))?;

    let pk = PublicKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| anyhow!("failed to parse P-256 public key from certificate: {e}"))?;
    let point = pk.to_encoded_point(false);
    let x: [u8; 32] = point.x().ok_or_else(|| anyhow!("missing x"))?.as_slice()
        .try_into().map_err(|_| anyhow!("pk x not 32 bytes"))?;
    let y: [u8; 32] = point.y().ok_or_else(|| anyhow!("missing y"))?.as_slice()
        .try_into().map_err(|_| anyhow!("pk y not 32 bytes"))?;

    Ok((bytes_to_registers(&x), bytes_to_registers(&y)))
}

/// Parse a DER-encoded ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }` as
/// found in an X.509 certificate's signatureValue BitString.
fn parse_ecdsa_der_sig(sig_bytes: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let sig = p256::ecdsa::Signature::from_der(sig_bytes)
        .map_err(|e| anyhow!("failed to parse DER ECDSA signature: {e}"))?;
    let (r, s) = sig.split_bytes();
    Ok((r.into(), s.into()))
}

/// Convert `ProofInputs` to `CircuitInputs` by parsing the leaf certificate
/// and encoding all values in the format expected by the Circom circuit.
///
/// The raw DER bytes are passed to the circuit directly (zero-padded to
/// MAX_CERT_BYTES) so that X509Parse can extract the TBS hash, SPKI, and
/// validity bounds inside the circuit — eliminating the key-mixing attack where
/// a prover could use cert A's TBS hash with key pair B.
pub fn proof_inputs_to_circuit(inputs: &ProofInputs) -> Result<CircuitInputs> {
    use der::Decode;
    use x509_cert::Certificate;

    let leaf_cert = Certificate::from_der(&inputs.cert_der)
        .map_err(|e| anyhow!("failed to parse leaf certificate: {e}"))?;

    // ---- Raw certificate bytes (zero-padded to MAX_CERT_BYTES) --------------
    // Each byte is a separate field element (decimal string).
    if inputs.cert_der.len() > MAX_CERT_BYTES {
        anyhow::bail!(
            "certificate is {} bytes, exceeds MAX_CERT_BYTES ({})",
            inputs.cert_der.len(), MAX_CERT_BYTES
        );
    }
    let cert_len = inputs.cert_der.len().to_string();
    let mut cert_der_padded: Vec<String> = inputs.cert_der
        .iter()
        .map(|b| b.to_string())
        .collect();
    cert_der_padded.resize(MAX_CERT_BYTES, "0".to_string());

    // ---- CA signature over TBSCertificate -----------------------------------
    // The signatureValue BitString in the X.509 Certificate contains a
    // DER-encoded ECDSA SEQUENCE { INTEGER r, INTEGER s }.
    let cert_sig_bytes = leaf_cert.signature.as_bytes()
        .ok_or_else(|| anyhow!("certificate signatureValue is not byte-aligned"))?;
    let (cert_r, cert_s) = parse_ecdsa_der_sig(cert_sig_bytes)?;
    let cert_sig_r = bytes_to_registers(&cert_r);
    let cert_sig_s = bytes_to_registers(&cert_s);

    // ---- Validity dates (off-circuit): removed — now computed in-circuit ----
    // The circuit parses notBefore/notAfter UTCTime fields directly from certDer
    // via UTCTimeToUnix inside X509Parse.  We only need the byte offsets here.

    // ---- CA (issuer) public key — public input ------------------------------
    let ca_pk_x: [u8; 32] = hex::decode(&inputs.ca_pubkey.x)?
        .try_into().map_err(|_| anyhow!("CA pubkey X must be 32 bytes"))?;
    let ca_pk_y: [u8; 32] = hex::decode(&inputs.ca_pubkey.y)?
        .try_into().map_err(|_| anyhow!("CA pubkey Y must be 32 bytes"))?;
    let ca_pub_key_x = bytes_to_registers(&ca_pk_x);
    let ca_pub_key_y = bytes_to_registers(&ca_pk_y);

    // ---- Claim hash and claim signature -------------------------------------
    let claim_hash_arr: [u8; 32] = inputs.claim_hash.clone()
        .try_into().map_err(|_| anyhow!("claim hash must be 32 bytes"))?;
    let claim_hash = bytes_to_registers(&claim_hash_arr);

    let claim_r: [u8; 32] = hex::decode(&inputs.sig_over_claim.r)?
        .try_into().map_err(|_| anyhow!("claim sig r must be 32 bytes"))?;
    let claim_s: [u8; 32] = hex::decode(&inputs.sig_over_claim.s)?
        .try_into().map_err(|_| anyhow!("claim sig s must be 32 bytes"))?;
    let claim_sig_r = bytes_to_registers(&claim_r);
    let claim_sig_s = bytes_to_registers(&claim_s);

    // ---- DER structural hints for X509Parse -----------------------------------
    // These are off-circuit byte offsets verified inside the circuit against
    // the certDer bytes.  We compute them here by walking the raw DER.
    let tbs_offset = compute_tbs_offset(&inputs.cert_der)?;
    let tbs_len    = compute_tbs_len(&inputs.cert_der, tbs_offset)?;

    // notBefore / notAfter UTCTime offsets for in-circuit date parsing.
    let not_before_offset = compute_not_before_offset(&inputs.cert_der, tbs_offset)?;
    let not_after_offset  = compute_not_after_offset(&inputs.cert_der, not_before_offset)?;

    // SHA-256 padding for the TBS slice — Sha256Bytes(1536) operates on this
    // pre-padded buffer in-circuit.
    let (tbs_padded_raw, tbs_hash_padded_len) =
        compute_tbs_sha256_padding(&inputs.cert_der, tbs_offset, tbs_len)?;
    let tbs_padded_bytes: Vec<String> = tbs_padded_raw.iter().map(|b| b.to_string()).collect();

    // To find spki_x_offset we need the raw X coordinate bytes, which we get
    // from the parsed certificate's SPKI (already extracted as ca_pk_x above,
    // but that's the *CA* key — here we need the *subject* key).
    let subject_spki = &leaf_cert.tbs_certificate.subject_public_key_info;
    let subject_pk_bytes = subject_spki.subject_public_key.as_bytes()
        .ok_or_else(|| anyhow!("subject public key not byte-aligned"))?;
    // subject_pk_bytes is the SEC 1 uncompressed point: 0x04 || X(32) || Y(32)
    if subject_pk_bytes.len() < 65 || subject_pk_bytes[0] != 0x04 {
        anyhow::bail!(
            "expected 65-byte uncompressed P-256 point (0x04||X||Y), got {} bytes starting with 0x{:02x}",
            subject_pk_bytes.len(), subject_pk_bytes[0]
        );
    }
    let subject_x: [u8; 32] = subject_pk_bytes[1..33].try_into()
        .map_err(|_| anyhow!("subject public key X is not 32 bytes"))?;
    let spki_x_offset = compute_spki_x_offset(&inputs.cert_der, &subject_x)?;

    Ok(CircuitInputs {
        ca_pub_key_x,
        ca_pub_key_y,
        claim_hash,
        photo_timestamp: inputs.photo_timestamp.to_string(),
        cert_der: cert_der_padded,
        cert_len,
        cert_sig_r,
        cert_sig_s,
        claim_sig_r,
        claim_sig_s,
        tbs_offset: tbs_offset.to_string(),
        tbs_len: tbs_len.to_string(),
        spki_x_offset: spki_x_offset.to_string(),
        not_before_offset: not_before_offset.to_string(),
        not_after_offset: not_after_offset.to_string(),
        tbs_hash_padded_len: tbs_hash_padded_len.to_string(),
        tbs_padded_bytes,
    })
}

/// Generate a ZK proof using snarkjs
/// 
/// This function:
/// 1. Writes the input JSON to a temp file
/// 2. Runs snarkjs to generate witness
/// 3. Runs snarkjs to generate proof
/// 4. Reads and returns the proof
pub fn generate_proof(
    circuit_inputs: &CircuitInputs,
    paths: &CircuitPaths,
) -> Result<SnarkProof> {
    use std::fs;
    use tempfile::tempdir;
    
    let temp = tempdir()?;
    let input_path = temp.path().join("input.json");
    let witness_path = temp.path().join("witness.wtns");
    let proof_path = temp.path().join("proof.json");
    let public_path = temp.path().join("public.json");
    
    // Write inputs to JSON
    let input_json = serde_json::to_string_pretty(circuit_inputs)?;
    fs::write(&input_path, &input_json)?;
    
    // Check that circuit files exist
    if !paths.circuit_wasm.exists() {
        bail!("Circuit WASM not found at {:?}. Run circuit build first.", paths.circuit_wasm);
    }
    if !paths.proving_key.exists() {
        bail!("Proving key not found at {:?}. Run trusted setup first.", paths.proving_key);
    }
    
    // Generate witness
    println!("Generating witness...");
    let wasm_dir = paths.circuit_wasm.parent().unwrap();
    let status = Command::new("node")
        .arg(wasm_dir.join("generate_witness.js"))
        .arg(&paths.circuit_wasm)
        .arg(&input_path)
        .arg(&witness_path)
        .status()
        .map_err(|e| anyhow!("failed to run witness generator: {e}"))?;
    
    if !status.success() {
        bail!("Witness generation failed");
    }
    
    // Generate proof
    println!("Generating proof...");
    let status = Command::new("npx")
        .args(["snarkjs", "groth16", "prove"])
        .arg(&paths.proving_key)
        .arg(&witness_path)
        .arg(&proof_path)
        .arg(&public_path)
        .status()
        .map_err(|e| anyhow!("failed to run snarkjs prove: {e}"))?;
    
    if !status.success() {
        bail!("Proof generation failed");
    }
    
    // Read proof
    let proof_json = fs::read_to_string(&proof_path)?;
    let proof_data: ProofData = serde_json::from_str(&proof_json)?;
    
    let public_json = fs::read_to_string(&public_path)?;
    let public_signals: Vec<String> = serde_json::from_str(&public_json)?;
    
    Ok(SnarkProof {
        proof: proof_data,
        public_signals,
    })
}

/// Verify a ZK proof using snarkjs
pub fn verify_proof(
    proof: &SnarkProof,
    paths: &CircuitPaths,
) -> Result<bool> {
    use std::fs;
    use tempfile::tempdir;
    
    // Check verification key exists
    if !paths.verification_key.exists() {
        bail!("Verification key not found at {:?}", paths.verification_key);
    }
    
    let temp = tempdir()?;
    let proof_path = temp.path().join("proof.json");
    let public_path = temp.path().join("public.json");
    
    // Write proof to file
    let proof_json = serde_json::to_string_pretty(&proof.proof)?;
    fs::write(&proof_path, &proof_json)?;
    
    // Write public signals to file
    let public_json = serde_json::to_string(&proof.public_signals)?;
    fs::write(&public_path, &public_json)?;
    
    // Run snarkjs verification
    println!("Running snarkjs groth16 verify...");
    let output = Command::new("npx")
        .args(["snarkjs", "groth16", "verify"])
        .arg(&paths.verification_key)
        .arg(&public_path)
        .arg(&proof_path)
        .output()
        .map_err(|e| anyhow!("failed to run snarkjs verify: {e}"))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    if !output.status.success() {
        eprintln!("snarkjs stderr: {stderr}");
        return Ok(false);
    }
    
    // snarkjs prints "OK!" when verification succeeds
    if stdout.contains("OK!") || stdout.contains("snarkJS: OK!") {
        Ok(true)
    } else {
        eprintln!("Unexpected snarkjs output: {stdout}");
        Ok(false)
    }
}

/// Prepare `ProofInputs` from manifest data and the signer's private key.
///
/// In a real deployment, this runs on the signer's device where they have
/// access to their private key.  The resulting `ProofInputs` is passed to
/// `proof_inputs_to_circuit` to produce the witness for the ZK prover.
pub fn prepare_inputs(
    manifest_data: &crate::ManifestData,
    signer_private_key: &[u8],
    ca_cert_der: &[u8],
) -> Result<ProofInputs> {
    use p256::ecdsa::{SigningKey, Signature, signature::hazmat::PrehashSigner};
    use p256::SecretKey;
    use der::Decode;
    use x509_cert::Certificate;

    // Parse the CA certificate to extract its public key.
    // This becomes `issuerPublicKey` in the circuit (a public input).
    let ca_cert = Certificate::from_der(ca_cert_der)
        .map_err(|e| anyhow!("failed to parse CA certificate: {e}"))?;
    let ca_pubkey =
        extract_p256_pubkey_components(&ca_cert.tbs_certificate.subject_public_key_info)?;

    // Parse the signer's private key (SEC1 DER or raw 32-byte scalar).
    let signing_key = if signer_private_key.len() == 32 {
        SigningKey::from_bytes(signer_private_key.into())
            .map_err(|e| anyhow!("invalid raw private key: {e}"))?
    } else {
        let secret_key = SecretKey::from_sec1_der(signer_private_key)
            .map_err(|e| anyhow!("failed to parse SEC1 private key: {e}"))?;
        SigningKey::from(secret_key)
    };

    // Sign the C2PA claim hash with the signer's private key.
    // The circuit proves possession of this key by verifying the resulting
    // signature against the subject public key from the leaf certificate.
    // Use prehash signing — claim_hash is already a SHA-256 digest.
    let signature: Signature = signing_key
        .sign_prehash(&manifest_data.claim_hash)
        .map_err(|e| anyhow!("failed to sign claim hash: {e}"))?;
    let sig_over_claim = signature_to_components(&signature)?;

    Ok(ProofInputs {
        cert_der: manifest_data.leaf_cert_der.clone(),
        sig_over_claim,
        claim_hash: manifest_data.claim_hash.clone(),
        ca_pubkey,
        photo_timestamp: manifest_data.photo_timestamp,
    })
}

fn extract_p256_pubkey_components(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Result<PublicKeyComponents> {
    use p256::PublicKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    
    // The SPKI contains the algorithm OID and the public key bits
    let pk_bytes = spki.subject_public_key.as_bytes()
        .ok_or_else(|| anyhow!("public key not byte-aligned"))?;
    
    let public_key = PublicKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| anyhow!("failed to parse P-256 public key: {e}"))?;
    
    let point = public_key.to_encoded_point(false);
    let x = point.x().ok_or_else(|| anyhow!("missing x coordinate"))?;
    let y = point.y().ok_or_else(|| anyhow!("missing y coordinate"))?;
    
    Ok(PublicKeyComponents {
        x: hex::encode(x),
        y: hex::encode(y),
    })
}

fn signature_to_components(sig: &p256::ecdsa::Signature) -> Result<SignatureComponents> {
    let (r, s) = sig.split_bytes();
    Ok(SignatureComponents {
        r: hex::encode(r),
        s: hex::encode(s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the TBS bytes and CA signature extracted from the test
    /// certificate are consistent — i.e., SHA-256(TBS) verifies under the CA
    /// public key.  If this test passes, the Rust-side circuit inputs are
    /// correct and any proof-verification failure is a circuit bug.
    #[test]
    fn cert_inputs_verify_offcircuit() {
        use sha2::{Sha256, Digest};
        use p256::ecdsa::{VerifyingKey, Signature, signature::hazmat::PrehashVerifier};
        use der::Decode;
        use x509_cert::Certificate;

        // Load test fixtures using CARGO_MANIFEST_DIR (zk-proofs/crates/c2pa-x509-zk-demo)
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixtures = manifest_dir.join("../../fixtures/certs");
        let cert_der = std::fs::read(fixtures.join("signer-cert.der"))
            .expect("signer-cert.der not found");
        let ca_cert_der = std::fs::read(fixtures.join("ca-cert.der"))
            .expect("ca-cert.der not found");

        // ---- Compute structural hints ----------------------------------------
        let tbs_offset = compute_tbs_offset(&cert_der).unwrap();
        let tbs_len = compute_tbs_len(&cert_der, tbs_offset).unwrap();
        let not_before_offset = compute_not_before_offset(&cert_der, tbs_offset).unwrap();
        let not_after_offset = compute_not_after_offset(&cert_der, not_before_offset).unwrap();
        let (_, tbs_hash_padded_len) =
            compute_tbs_sha256_padding(&cert_der, tbs_offset, tbs_len).unwrap();

        eprintln!("tbs_offset={tbs_offset}, tbs_len={tbs_len}");
        eprintln!("not_before_offset={not_before_offset}, not_after_offset={not_after_offset}");
        eprintln!("tbs_hash_padded_len={tbs_hash_padded_len}");
        eprintln!("cert tag at tbs_offset: 0x{:02x}, len-type: 0x{:02x}",
            cert_der[tbs_offset], cert_der[tbs_offset + 1]);

        // ---- Print notBefore UTCTime bytes (first 14 bytes from offset) ------
        let nb_bytes = &cert_der[not_before_offset..not_before_offset + 15];
        eprintln!("notBefore raw: {:02x?}", nb_bytes);
        let na_bytes = &cert_der[not_after_offset..not_after_offset + 15];
        eprintln!("notAfter  raw: {:02x?}", na_bytes);

        // ---- Verify CA signature off-circuit ---------------------------------
        let tbs_bytes = &cert_der[tbs_offset..tbs_offset + 4 + tbs_len];
        let tbs_hash: [u8; 32] = Sha256::digest(tbs_bytes).into();
        eprintln!("SHA-256(TBS) = {:02x?}", &tbs_hash);

        let cert = Certificate::from_der(&cert_der).unwrap();
        let ca_cert = Certificate::from_der(&ca_cert_der).unwrap();

        let ca_pk_bytes = ca_cert.tbs_certificate.subject_public_key_info
            .subject_public_key.as_bytes().unwrap();
        let ca_vk = VerifyingKey::from_sec1_bytes(ca_pk_bytes).unwrap();

        let cert_sig_bytes = cert.signature.as_bytes().unwrap();
        let (cert_r, cert_s) = parse_ecdsa_der_sig(cert_sig_bytes).unwrap();
        eprintln!("certSigR = {:02x?}", &cert_r);
        eprintln!("certSigS = {:02x?}", &cert_s);

        let sig = Signature::from_scalars(
            p256::FieldBytes::clone_from_slice(&cert_r),
            p256::FieldBytes::clone_from_slice(&cert_s),
        ).expect("failed to construct signature");

        ca_vk.verify_prehash(&tbs_hash, &sig)
            .expect("CA signature verification FAILED — circuit inputs are wrong");

        eprintln!("✓ CA signature verification PASSED");
    }
}
