//! Common types for X.509 ZK proof generation and verification

use serde::{Deserialize, Serialize};

/// Data extracted from a C2PA manifest for ZK proof generation
#[derive(Debug, Clone)]
pub struct ManifestData {
    /// The C2PA claim hash (32 bytes SHA-256)
    pub claim_hash: Vec<u8>,
    /// DER-encoded leaf certificate from the COSE x5chain
    pub leaf_cert_der: Vec<u8>,
    /// DER-encoded CA certificate(s)
    pub ca_certs_der: Vec<Vec<u8>>,
    /// The original COSE signature bytes
    pub cose_signature: Vec<u8>,
    /// Unix timestamp (seconds since epoch) of when the photo was taken.
    /// Used as the `photoTimestamp` public input for the validity-period check.
    /// Defaults to 0 if not available from the manifest metadata.
    pub photo_timestamp: u64,
}

/// Parameters for trusted CA verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedCaParams {
    /// DER-encoded CA certificate
    pub ca_cert_der: Vec<u8>,
    /// Expected issuer DN (optional, for validation)
    pub expected_issuer: Option<String>,
}

impl TrustedCaParams {
    pub fn from_pem_file(path: &std::path::Path) -> anyhow::Result<Self> {
        use std::fs;
        let pem_contents = fs::read_to_string(path)?;
        Self::from_pem(&pem_contents)
    }
    
    pub fn from_pem(pem_contents: &str) -> anyhow::Result<Self> {
        // Simple PEM parsing - extract base64 between markers
        let start_marker = "-----BEGIN CERTIFICATE-----";
        let end_marker = "-----END CERTIFICATE-----";
        
        let start = pem_contents.find(start_marker)
            .ok_or_else(|| anyhow::anyhow!("missing PEM start marker"))?;
        let end = pem_contents.find(end_marker)
            .ok_or_else(|| anyhow::anyhow!("missing PEM end marker"))?;
        
        let base64_content: String = pem_contents[start + start_marker.len()..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        
        let ca_cert_der = base64::engine::general_purpose::STANDARD
            .decode(&base64_content)?;
        
        Ok(Self {
            ca_cert_der,
            expected_issuer: None,
        })
    }
    
    pub fn from_der_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let ca_cert_der = std::fs::read(path)?;
        Ok(Self {
            ca_cert_der,
            expected_issuer: None,
        })
    }
}

use base64::Engine;
