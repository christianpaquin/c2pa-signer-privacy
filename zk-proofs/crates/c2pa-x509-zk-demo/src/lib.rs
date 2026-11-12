//! C2PA X.509 ZK Anonymizer Library
//!
//! This crate provides tools for anonymizing C2PA manifests by replacing
//! X.509/COSE signatures with zero-knowledge proofs that prove:
//! 1. The signer's certificate was issued by a trusted CA
//! 2. The signer possessed the private key and signed the asset-binding digest
//!
//! The final manifest only reveals the CA issuer, not the signer's identity.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub mod circuit;
pub mod circuit_native;
pub mod jumbf;
pub mod local_tsa;
pub mod manifest;
pub mod original_signature;
pub mod proving_key;
pub mod scrub;
pub mod third_party;
pub mod trust;
pub mod types;
pub mod zk_signature;

#[cfg(test)]
pub(crate) mod test_pki;

// Re-exports
pub use circuit::{
    CircuitInputs, CircuitPaths, ProofInputs, ProofOutputs, PublicKeyComponents,
    SignatureComponents, SnarkProof, bytes_to_registers, pubkey_registers_from_der,
    proof_inputs_to_circuit,
};
pub use circuit_native::{
    BuildManifest, NativeCircuitPaths, NativeProof, ProveOptions, WitnessRejected, native_setup, native_setup_with, file_sha256,
    check_witness, circuit_builder, compute_checked_witness, compute_witness, generate_proof_native, generate_proof_native_with,
    load_r1cs, load_proving_key, load_verifying_key, prepare_verifying_key, prove_circuit, read_witness,
    verify_proof_native, verify_proof_prepared, write_witness,
};
pub use manifest::{
    compute_manifest_stripped_asset_digest,
    extract_manifest_data,
    rewrite_manifest_with_zk_proof,
};
pub use trust::{
    issuing_path_for, pem_to_der_certs, spki_key_id, validate_issuing_chain, verify_issued_by, TrustList,
};
pub use types::*;

/// Assertion type marker for X.509 ZK proofs
pub const ASSERTION_TYPE: &str = "x509-zk-signer-proof";
/// 0.2 adds the optional artifact identifiers (`circuit_r1cs_sha256`,
/// `verifying_key_sha256`); 0.1 assertions are still accepted without them.
pub const ASSERTION_VERSION: &str = "0.2";
pub const CIRCUIT_ID: &str = "x509-issue-possession-v0";
pub const BACKEND: &str = "circom-groth16";
pub const CLAIM_GENERATOR: &str = "c2pa-x509-zk-demo/0.1";

/// The ZK proof assertion embedded in anonymized manifests
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509ZkSignerProofAssertion {
    #[serde(rename = "type")]
    pub assertion_type: String,
    pub version: String,
    /// Canonical issuer DN (e.g., "CN=Example Root CA,O=Example Org,C=US")
    pub issuer: String,
    /// Hex SHA-256 of the issuing CA's SubjectPublicKeyInfo (see `spki_key_id`)
    pub issuer_key_id: String,
    /// Hex-encoded manifest-stripped asset digest used for proof binding.
    pub claim_hash: String,
    /// Base64-encoded SNARK proof
    pub proof: String,
    /// Circuit identifier for proof verification
    pub circuit_id: String,
    /// Proving backend (e.g., "circom-groth16")
    pub backend: String,
    /// Hex SHA-256 of the circuit's .r1cs the proof was made for (v0.2+).
    /// A diagnostic: verifiers use their own trusted keys, never keys chosen
    /// from this value, and Groth16 verification decides validity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_r1cs_sha256: Option<String>,
    /// Hex SHA-256 of the verifying key matching the proving key used (v0.2+).
    /// A diagnostic, as above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_key_sha256: Option<String>,
}

impl X509ZkSignerProofAssertion {
    pub fn new(
        issuer: String,
        issuer_key_id: String,
        claim_hash: String,
        proof: String,
    ) -> Self {
        Self {
            assertion_type: ASSERTION_TYPE.to_string(),
            version: ASSERTION_VERSION.to_string(),
            issuer,
            issuer_key_id,
            claim_hash,
            proof,
            circuit_id: CIRCUIT_ID.to_string(),
            backend: BACKEND.to_string(),
            circuit_r1cs_sha256: None,
            verifying_key_sha256: None,
        }
    }

    /// Record which circuit and keys produced the proof.
    pub fn with_artifacts(mut self, manifest: &circuit_native::BuildManifest) -> Self {
        self.circuit_r1cs_sha256 = Some(manifest.r1cs_sha256.clone());
        self.verifying_key_sha256 = Some(manifest.verifying_key_sha256.clone());
        self
    }
}

/// Extract the subject DN from a DER-encoded X.509 certificate
pub fn extract_subject_dn(cert_der: &[u8]) -> Result<String> {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("failed to parse X.509 certificate: {e}"))?;

    Ok(cert.tbs_certificate.subject.to_string())
}

/// Extract the issuer DN from a DER-encoded X.509 certificate
pub fn extract_issuer_dn(cert_der: &[u8]) -> Result<String> {
    use der::Decode;
    use x509_cert::Certificate;
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("failed to parse X.509 certificate: {e}"))?;
    
    Ok(cert.tbs_certificate.issuer.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v0_1_assertion_without_artifacts_still_parses() {
        let json = r#"{"type":"x509-zk-signer-proof","version":"0.1","issuer":"CN=CA","issuer_key_id":"ab",
            "claim_hash":"cd","proof":"ef","circuit_id":"x509-issue-possession-v0","backend":"circom-groth16"}"#;
        let parsed: X509ZkSignerProofAssertion = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.version, "0.1");
        assert_eq!(parsed.circuit_r1cs_sha256, None);
        assert_eq!(parsed.verifying_key_sha256, None);
    }

    #[test]
    fn assertion_serialization_roundtrip() {
        let assertion = X509ZkSignerProofAssertion::new(
            "CN=Test CA,O=Test,C=US".to_string(),
            "deadbeef01234567".to_string(),
            "abc123".to_string(),
            "base64proof==".to_string(),
        );
        
        let json = serde_json::to_string(&assertion).unwrap();
        let parsed: X509ZkSignerProofAssertion = serde_json::from_str(&json).unwrap();
        
        assert_eq!(assertion, parsed);
        assert_eq!(parsed.assertion_type, ASSERTION_TYPE);
        assert_eq!(parsed.circuit_id, CIRCUIT_ID);
    }
}
