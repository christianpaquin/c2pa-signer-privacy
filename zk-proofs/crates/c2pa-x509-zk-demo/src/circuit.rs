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
    /// Unix timestamp of when the photo was taken (public, decimal string)
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
    /// Certificate validity start as Unix timestamp (private, decimal string)
    pub cert_not_before: String,
    /// Certificate validity end as Unix timestamp (private, decimal string)
    pub cert_not_after: String,
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
    /// Unix timestamp when the photo was taken (public)
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

/// Convert a 32-byte value to k registers of n bits (circom BigInt format).
/// Registers are least-significant first.
fn bytes_to_registers(bytes: &[u8; 32]) -> [String; K_REGISTERS] {
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

/// Parse a DER-encoded ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }` as
/// found in an X.509 certificate's signatureValue BitString.
fn parse_ecdsa_der_sig(sig_bytes: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let sig = p256::ecdsa::Signature::from_der(sig_bytes)
        .map_err(|e| anyhow!("failed to parse DER ECDSA signature: {e}"))?;
    let (r, s) = sig.split_bytes();
    Ok((r.into(), s.into()))
}

/// Convert an x509-cert `Time` value to a Unix timestamp (seconds since epoch).
fn validity_time_to_unix(time: &x509_cert::time::Time) -> Result<u64> {
    use x509_cert::time::Time;
    let system_time: std::time::SystemTime = match time {
        Time::UtcTime(t) => std::time::SystemTime::try_from(*t)
            .map_err(|_| anyhow!("UtcTime out of SystemTime range"))?,
        Time::GeneralTime(t) => std::time::SystemTime::try_from(*t)
            .map_err(|_| anyhow!("GeneralizedTime out of SystemTime range"))?,
    };
    system_time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d: std::time::Duration| d.as_secs())
        .map_err(|e| anyhow!("certificate time before Unix epoch: {e}"))
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

    // ---- Validity dates -----------------------------------------------------
    let cert_not_before = validity_time_to_unix(
        &leaf_cert.tbs_certificate.validity.not_before,
    )?.to_string();
    let cert_not_after = validity_time_to_unix(
        &leaf_cert.tbs_certificate.validity.not_after,
    )?.to_string();

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
        cert_not_before,
        cert_not_after,
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
    println!("Generating proof (this may take ~30 seconds)...");
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
