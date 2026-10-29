//! Manifest handling for reading and rewriting C2PA assets

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use c2pa::{hash_stream_by_alg, Reader, Builder, Signer, SigningAlg};
use ciborium::Value as CborValue;
use coset::{CoseSign1, CoseSign1Builder, Header, TaggedCborSerializable};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use tempfile::Builder as TempFileBuilder;

use crate::{ManifestData, X509ZkSignerProofAssertion, ASSERTION_TYPE, CLAIM_GENERATOR};

/// Extract manifest data needed for ZK proof generation.
/// 
/// This reads an existing C2PA-signed asset and extracts:
/// - A verifier-recomputable digest of the manifest-stripped asset bytes
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
    
    // Bind the proof to the asset bytes with all C2PA JUMBF removed.
    //
    // This is not the spec claim hash, but unlike the previous surrogate hash
    // it is derived from the actual file content and can be recomputed by the
    // verifier from the anonymized asset after removing its manifest.
    let claim_hash = compute_manifest_stripped_asset_digest(asset_path)?;

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
        // Use the current time as the anonymization-time timestamp consumed by
        // the circuit's validity-period check.
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

fn compute_asset_digest(asset_path: &Path) -> Result<Vec<u8>> {
    let file = File::open(asset_path)
        .map_err(|err| anyhow!("failed to open asset {asset_path:?}: {err}"))?;
    let mut reader = BufReader::new(file);
    hash_stream_by_alg("sha256", &mut reader, None, false)
        .map_err(|err| anyhow!("failed to compute asset digest for {asset_path:?}: {err}"))
}

/// Compute a verifier-recomputable digest over the asset bytes after stripping
/// all embedded C2PA manifests/JUMBF data.
pub fn compute_manifest_stripped_asset_digest(asset_path: &Path) -> Result<Vec<u8>> {
    let suffix = asset_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();

    let temp_file = TempFileBuilder::new()
        .prefix("c2pa-x509-zk-")
        .suffix(&suffix)
        .tempfile()
        .map_err(|err| anyhow!("failed to create temp file for digest computation: {err}"))?;

    fs::copy(asset_path, temp_file.path())
        .map_err(|err| anyhow!("failed to copy asset for digest computation: {err}"))?;
    c2pa::jumbf_io::remove_jumbf_from_file(temp_file.path())
        .map_err(|err| anyhow!("failed to remove embedded manifest for digest computation: {err}"))?;

    compute_asset_digest(temp_file.path())
}

/// Rewrite a manifest to replace the COSE signature with a ZK proof assertion.
///
/// The output carries no certificates: the signer's leaf certificate is the
/// identity the proof hides, and the verifier supplies the trusted CA itself.
pub fn rewrite_manifest_with_zk_proof(
    input_path: &Path,
    output_path: &Path,
    assertion: X509ZkSignerProofAssertion,
) -> Result<()> {
    // Create a new manifest with the ZK assertion using the Builder API
    let definition = serde_json::json!({
        "claim_generator_info": [{ "name": CLAIM_GENERATOR, "version": "0.1" }]
    });
    let mut builder = Builder::from_json(&definition.to_string())
        .map_err(|e| anyhow!("failed to create builder: {e}"))?;
    
    builder.add_assertion(ASSERTION_TYPE, &assertion)
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
    
    builder.sign_file(&signer, input_path, output_path)
        .map_err(|e| anyhow!("failed to embed manifest: {e}"))?;
    
    Ok(())
}

/// COSE algorithm value for ZK proofs, in the private-use range (below -65536).
const ZK_COSE_ALG: i64 = -65538;  // Different from BBS (-65537)
/// Critical header label for ZK extension.
const CRIT_LABEL: &str = "c2pa-x509-zk";
/// Unprotected header labels used to pad the COSE structure, as in c2pa-rs.
const PAD_LABEL: &str = "pad";
const PAD2_LABEL: &str = "pad2";

/// Custom signer that outputs a COSE_Sign1 with our ZK proof.
///
/// Unlike a standard C2PA signer, it deliberately emits no `x5chain` header:
/// embedding the signer's certificate would reveal the identity the proof hides.
struct ZkProofSigner {
    proof: Vec<u8>,
}

impl ZkProofSigner {
    fn new(proof: Vec<u8>) -> Self {
        Self { proof }
    }

    /// Build a COSE_Sign1 structure with our custom algorithm, padded to
    /// exactly `end_size` bytes.
    fn build_cose(&self, claim_bytes: &[u8], end_size: usize) -> c2pa::Result<Vec<u8>> {
        // ZK extension map with circuit info
        let zk_ext = CborValue::Map(vec![
            (CborValue::Text("circuit".into()), CborValue::Text(crate::CIRCUIT_ID.into())),
            (CborValue::Text("backend".into()), CborValue::Text(crate::BACKEND.into())),
            (CborValue::Text("version".into()), CborValue::Text(crate::ASSERTION_VERSION.into())),
        ]);

        // Build the protected header with private-use algorithm. The extension
        // is marked critical (COSE `crit`, label 2), so verifiers that don't
        // understand it must reject the signature.
        // No x5chain (header param 33): see the ZkProofSigner doc comment.
        let protected = Header {
            alg: Some(coset::Algorithm::PrivateUse(ZK_COSE_ALG)),
            crit: vec![coset::RegisteredLabel::Text(CRIT_LABEL.into())],
            rest: vec![(coset::Label::Text(CRIT_LABEL.into()), zk_ext)],
            ..Default::default()
        };

        let mut sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(claim_bytes.to_vec())
            .create_signature(&[], |_| self.proof.clone())
            .build();

        // Detached payload, as in standard C2PA signatures
        sign1.payload = None;
        pad_cose_sign1(sign1, end_size).map_err(|msg| {
            c2pa::Error::OtherError(Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg)))
        })
    }
}

/// Serialize `sign1` padded to exactly `end_size` bytes (c2pa-rs requires the
/// signature to fill its reserved space). The padding goes in a `pad` byte
/// string in the unprotected header, as c2pa-rs does, rather than as trailing
/// bytes, which strict COSE parsers reject.
fn pad_cose_sign1(sign1: CoseSign1, end_size: usize) -> Result<Vec<u8>, String> {
    // A CBOR byte string's length prefix grows at 24 and 256 bytes, so a single
    // pad cannot hit sizes just past those boundaries. An empty second pad
    // (`pad2`) shifts the required pad length away from the boundary.
    for pad2 in [false, true] {
        let serialize = |pad_len: usize| {
            let mut padded = sign1.clone();
            let rest = &mut padded.unprotected.rest;
            rest.push((coset::Label::Text(PAD_LABEL.into()), CborValue::Bytes(vec![0u8; pad_len])));
            if pad2 {
                rest.push((coset::Label::Text(PAD2_LABEL.into()), CborValue::Bytes(Vec::new())));
            }
            padded.to_tagged_vec().map_err(|e| format!("{e:?}"))
        };

        // The pad entry adds its label and a length prefix on top of the
        // padding itself, so search just below the raw size gap.
        let Some(gap) = end_size.checked_sub(serialize(0)?.len()) else {
            continue;
        };
        for pad_len in (gap.saturating_sub(16)..=gap).rev() {
            let cose = serialize(pad_len)?;
            if cose.len() == end_size {
                return Ok(cose);
            }
        }
    }
    Err(format!("cannot pad COSE structure to exactly {end_size} bytes"))
}

impl Signer for ZkProofSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        // When direct_cose_handling is true, `data` is the claim bytes.
        // c2pa-rs expects the signature to be EXACTLY reserve_size bytes.
        self.build_cose(data, self.reserve_size())
    }

    fn alg(&self) -> SigningAlg {
        // Ignored when direct_cose_handling() returns true
        SigningAlg::Ps256
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        // No certificates: the signer's identity must not appear in the output.
        Ok(Vec::new())
    }

    fn reserve_size(&self) -> usize {
        // Account for COSE overhead + proof + headers + padding
        self.proof.len().saturating_add(8192)
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

#[cfg(test)]
mod tests {
    use super::{ZkProofSigner, CRIT_LABEL, PAD_LABEL, ZK_COSE_ALG};
    use c2pa::Signer;
    use coset::{CoseSign1, TaggedCborSerializable};

    #[test]
    fn zk_signer_emits_no_certificates() {
        let signer = ZkProofSigner::new(vec![9u8, 8, 7]);
        assert!(signer.certs().unwrap().is_empty());

        let cose = CoseSign1::from_tagged_slice(&signer.sign(b"claim").unwrap()).unwrap();
        let x5chain = coset::Label::Int(33);
        assert!(
            !cose.protected.header.rest.iter().chain(&cose.unprotected.rest).any(|(label, _)| *label == x5chain),
            "COSE headers must not carry an x5chain"
        );
    }

    #[test]
    fn zk_signer_emits_conformant_cose() {
        let proof = vec![9u8; 1000];
        let signer = ZkProofSigner::new(proof.clone());
        let bytes = signer.sign(b"claim").unwrap();

        // Exactly fills the reserved space, with no trailing bytes: strict
        // parsing rejects both trailing data and non-private-use algorithms.
        assert_eq!(bytes.len(), signer.reserve_size());
        let cose = CoseSign1::from_tagged_slice(&bytes).unwrap();

        assert!(ZK_COSE_ALG < coset::iana::ALGORITHM_PRIVATE_USE_MAX);
        assert_eq!(cose.protected.header.alg, Some(coset::Algorithm::PrivateUse(ZK_COSE_ALG)));
        assert_eq!(cose.protected.header.crit, vec![coset::RegisteredLabel::Text(CRIT_LABEL.into())]);
        assert!(cose.protected.header.rest.iter().any(|(label, _)| *label == coset::Label::Text(CRIT_LABEL.into())));
        assert!(cose.unprotected.rest.iter().any(|(label, _)| *label == coset::Label::Text(PAD_LABEL.into())));
        assert_eq!(cose.payload, None);
        assert_eq!(cose.signature, proof);
    }

    #[test]
    fn pad_cose_sign1_hits_every_size() {
        let signer = ZkProofSigner::new(vec![9u8, 8, 7]);
        // The structure cannot shrink below its size with an empty pad.
        let min_size = (0..).find(|&n| signer.build_cose(b"claim", n).is_ok()).unwrap();
        // Every larger size is reachable, including across the CBOR
        // length-prefix boundaries at 24 and 256 bytes of padding.
        for end_size in min_size..min_size + 400 {
            let bytes = signer.build_cose(b"claim", end_size).unwrap();
            assert_eq!(bytes.len(), end_size);
            CoseSign1::from_tagged_slice(&bytes).unwrap();
        }
    }
}
