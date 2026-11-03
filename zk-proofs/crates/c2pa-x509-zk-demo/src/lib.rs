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
pub mod manifest;
pub mod trust;
pub mod types;

#[cfg(test)]
pub(crate) mod test_pki;

// Re-exports
pub use circuit::{
    CircuitInputs, CircuitPaths, ProofInputs, ProofOutputs, PublicKeyComponents,
    SignatureComponents, SnarkProof, bytes_to_registers, pubkey_registers_from_der,
    proof_inputs_to_circuit,
};
pub use circuit_native::{
    NativeCircuitPaths, NativeProof, native_setup, 
    generate_proof_native, verify_proof_native,
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
pub const ASSERTION_VERSION: &str = "0.1";
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
        }
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
