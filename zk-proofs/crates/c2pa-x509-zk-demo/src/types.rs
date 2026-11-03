//! Common types for X.509 ZK proof generation and verification

/// Data extracted from a C2PA manifest for ZK proof generation
#[derive(Debug, Clone)]
pub struct ManifestData {
    /// The manifest-stripped asset digest used as the proof's public message.
    ///
    /// The field name is retained for compatibility with the current circuit
    /// signal layout (`claimHash`).
    pub claim_hash: Vec<u8>,
    /// DER-encoded leaf certificate from the COSE x5chain
    pub leaf_cert_der: Vec<u8>,
    /// DER-encoded CA certificate(s)
    pub ca_certs_der: Vec<Vec<u8>>,
    /// The original COSE signature bytes
    pub cose_signature: Vec<u8>,
    /// Unix timestamp (seconds since epoch) of when the asset was anonymized.
    /// Used as the `photoTimestamp` public input for the validity-period check.
    /// Currently set by the editor at processing time.
    pub photo_timestamp: u64,
}
