//! Manifest handling for reading and rewriting C2PA assets

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use c2pa::{Reader, Manifest, Signer, SigningAlg};
use ciborium::Value as CborValue;
use coset::{CoseSign1Builder, Header};
use std::path::Path;
use std::fs;

use crate::{ManifestData, X509ZkSignerProofAssertion, ASSERTION_TYPE, CLAIM_GENERATOR};

/// DER-encoded demo certificates (same as fixtures/certs but embedded)
const DEMO_LEAF_CERT: &[u8] = include_bytes!("../../../fixtures/certs/signer-cert.der");
const DEMO_CA_CERT: &[u8] = include_bytes!("../../../fixtures/certs/ca-cert.der");

/// Extract manifest data needed for ZK proof generation
/// 
/// This reads an existing C2PA-signed asset and extracts:
/// - The claim hash
/// - The leaf certificate from the COSE x5chain
/// - The CA certificate(s)
pub fn extract_manifest_data(asset_path: &Path) -> Result<ManifestData> {
    let reader = Reader::from_file(asset_path)
        .map_err(|e| anyhow!("failed to read manifest: {e}"))?;
    
    let manifest = reader.active_manifest()
        .ok_or_else(|| anyhow!("no active manifest in asset"))?;
    
    // Get the signature info
    let signature = manifest.signature_info()
        .ok_or_else(|| anyhow!("no signature info in manifest"))?;
    
    // Extract certificate chain from signature
    let cert_chain = signature.cert_chain();
    if cert_chain.is_empty() {
        bail!("no certificate chain in signature");
    }
    
    // Parse the PEM certificate chain
    let certs = parse_pem_chain(cert_chain)?;
    if certs.is_empty() {
        bail!("empty certificate chain");
    }
    
    let leaf_cert_der = certs[0].clone();
    let ca_certs_der = certs[1..].to_vec();
    
    // C2PA claim hash — demo limitation
    //
    // In production, the ZK proof would be generated *at signing time*, giving
    // the prover direct access to the claim bytes and their SHA-256 hash before
    // or during the COSE signing step.  Doing so after signing requires access
    // to the raw claim CBOR, which c2pa-rs 0.33 does not expose through its
    // public API.
    //
    // For this demo we compute a deterministic surrogate claim hash from the
    // leaf certificate and manifest identifiers.  This hash is self-consistent:
    // the same value is embedded in the ZK proof (via `prepare_inputs`) and
    // stored in the assertion's `claim_hash` field, so `verify.rs`'s public-
    // signal binding check passes.  It does NOT equal the actual C2PA claim
    // hash, so it does not provide spec-compliant content binding.
    let claim_hash = compute_claim_hash_workaround(&leaf_cert_der, manifest)?;

    // The original COSE signature bytes are not extracted here.  `prepare_inputs`
    // does not use them — it re-signs `claim_hash` with the caller-supplied
    // private key.  The field is retained in `ManifestData` for future use if
    // extraction becomes possible (e.g. to skip re-signing and use the original
    // signer's ECDSA components directly as circuit witnesses).
    let cose_signature = Vec::new();

    Ok(ManifestData {
        claim_hash,
        leaf_cert_der,
        ca_certs_der,
        cose_signature,
        // Use the current time as a conservative photo_timestamp.
        // A real implementation would read this from the manifest's
        // creation date claim or EXIF metadata.
        photo_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

/// Parse a PEM certificate chain into DER bytes
fn parse_pem_chain(pem_chain: &str) -> Result<Vec<Vec<u8>>> {
    use base64::Engine;
    
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    
    let mut certs = Vec::new();
    let mut remaining = pem_chain;
    
    while let Some(start) = remaining.find(start_marker) {
        let after_start = &remaining[start + start_marker.len()..];
        let end = after_start.find(end_marker)
            .ok_or_else(|| anyhow!("malformed PEM: missing end marker"))?;
        
        let base64_content: String = after_start[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        
        let der = base64::engine::general_purpose::STANDARD
            .decode(&base64_content)
            .map_err(|e| anyhow!("invalid base64 in PEM: {e}"))?;
        
        certs.push(der);
        remaining = &after_start[end + end_marker.len()..];
    }
    
    Ok(certs)
}

/// Demo surrogate claim hash.
///
/// Computes SHA-256 over the leaf certificate bytes followed by the manifest's
/// label and title strings.  The result uniquely identifies the manifest +
/// certificate combination as far as the demo is concerned.
///
/// This is NOT the C2PA spec claim hash (SHA-256 of the COSE-protected claim
/// CBOR).  See `extract_manifest_data` for the rationale.
fn compute_claim_hash_workaround(leaf_cert_der: &[u8], manifest: &c2pa::Manifest) -> Result<Vec<u8>> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();

    // Bind to the leaf certificate — changes if the certificate changes.
    hasher.update(leaf_cert_der);
    
    // Bind to the manifest's stable identifiers.
    if let Some(label) = manifest.label() {
        hasher.update(label.as_bytes());
    }
    if let Some(title) = manifest.title() {
        hasher.update(title.as_bytes());
    }
    
    Ok(hasher.finalize().to_vec())
}

/// Rewrite a manifest to replace the COSE signature with a ZK proof assertion
pub fn rewrite_manifest_with_zk_proof(
    input_path: &Path,
    output_path: &Path,
    assertion: X509ZkSignerProofAssertion,
) -> Result<()> {
    // Create a new manifest with the ZK assertion
    let mut manifest = Manifest::new(CLAIM_GENERATOR);
    
    manifest.set_asset_from_path(input_path)
        .map_err(|e| anyhow!("failed to set asset: {e}"))?;
    
    manifest.add_labeled_assertion(ASSERTION_TYPE, &assertion)
        .map_err(|e| anyhow!("failed to add ZK assertion: {e}"))?;
    
    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    
    // Use our custom signer that embeds the ZK proof as the signature
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(&assertion.proof)
        .unwrap_or_else(|_| assertion.proof.as_bytes().to_vec());
    
    let signer = ZkProofSigner::new(proof_bytes);
    
    manifest.embed(input_path, output_path, &signer)
        .map_err(|e| anyhow!("failed to embed manifest: {e}"))?;
    
    Ok(())
}

/// Private-use COSE algorithm value for ZK proofs.
const ZK_COSE_ALG: i64 = -65534;  // Different from BBS (-65535)
/// Critical header label for ZK extension.
const CRIT_LABEL: &str = "c2pa-x509-zk";

/// Custom signer that outputs a COSE_Sign1 with our ZK proof
struct ZkProofSigner {
    proof: Vec<u8>,
}

impl ZkProofSigner {
    fn new(proof: Vec<u8>) -> Self {
        Self { proof }
    }

    /// Build a COSE_Sign1 structure with our custom algorithm.
    fn build_cose(&self, claim_bytes: &[u8]) -> c2pa::Result<Vec<u8>> {
        use coset::TaggedCborSerializable;
        
        // Get certificate chain
        let certs = self.certs()?;
        let x5chain = if certs.len() == 1 {
            CborValue::Bytes(certs[0].clone())
        } else {
            CborValue::Array(certs.into_iter().map(CborValue::Bytes).collect())
        };

        // ZK extension map with circuit info
        let zk_ext = CborValue::Map(vec![
            (CborValue::Text("circuit".into()), CborValue::Text(crate::CIRCUIT_ID.into())),
            (CborValue::Text("backend".into()), CborValue::Text(crate::BACKEND.into())),
            (CborValue::Text("version".into()), CborValue::Text(crate::ASSERTION_VERSION.into())),
        ]);

        // Build the protected header with private-use algorithm
        let protected = Header {
            alg: Some(coset::Algorithm::PrivateUse(ZK_COSE_ALG)),
            rest: vec![
                // x5chain (header param 33)
                (coset::Label::Int(33), x5chain),
                // crit header
                (coset::Label::Text("crit".into()), CborValue::Array(vec![CborValue::Text(CRIT_LABEL.into())])),
                // zk extension map
                (coset::Label::Text(CRIT_LABEL.into()), zk_ext),
            ],
            ..Default::default()
        };

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(claim_bytes.to_vec())
            .create_signature(&[], |_| self.proof.clone())
            .build();

        // Remove payload (detached) and serialize as tagged
        let mut sign1_detached = sign1;
        sign1_detached.payload = None;
        sign1_detached
            .to_tagged_vec()
            .map_err(|e| c2pa::Error::OtherError(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("{e:?}")
            ))))
    }
}

impl Signer for ZkProofSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        // When direct_cose_handling is true, `data` is the claim bytes
        let cose = self.build_cose(data)?;
        
        // c2pa-rs expects the signature to be EXACTLY reserve_size bytes
        if cose.len() > self.reserve_size() {
            return Err(c2pa::Error::OtherError(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("COSE structure {} > reserve_size {}", cose.len(), self.reserve_size()),
            ))));
        }
        
        // Pad to exact reserve_size
        let mut padded = cose;
        padded.resize(self.reserve_size(), 0);
        Ok(padded)
    }

    fn alg(&self) -> SigningAlg {
        // Ignored when direct_cose_handling() returns true
        SigningAlg::Ps256
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(vec![DEMO_LEAF_CERT.to_vec(), DEMO_CA_CERT.to_vec()])
    }

    fn reserve_size(&self) -> usize {
        // Account for COSE overhead + proof + certs + headers + padding
        self.proof
            .len()
            .saturating_add(DEMO_LEAF_CERT.len())
            .saturating_add(DEMO_CA_CERT.len())
            .saturating_add(8192)
    }

    fn direct_cose_handling(&self) -> bool {
        true
    }
}

/// Extract the ZK assertion from an anonymized manifest
pub fn extract_zk_assertion(asset_path: &Path) -> Result<X509ZkSignerProofAssertion> {
    let reader = Reader::from_file(asset_path)
        .map_err(|e| anyhow!("failed to read manifest: {e}"))?;
    
    let manifest = reader.active_manifest()
        .ok_or_else(|| anyhow!("no active manifest in asset"))?;
    
    manifest.find_assertion(ASSERTION_TYPE)
        .map_err(|e| anyhow!("missing {ASSERTION_TYPE} assertion: {e}"))
}
