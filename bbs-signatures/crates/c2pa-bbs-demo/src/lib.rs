use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use c2pa::{hash_stream_by_alg, Manifest, Reader, SigningAlg, Signer};
use ciborium::Value as CborValue;
use coset::{CoseSign1Builder, Header, TaggedCborSerializable};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{
            KeyPair,
            BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
            BBS_BLS12381G1_SECRET_KEY_LENGTH,
            MIN_KEY_GEN_IKM_LENGTH,
        },
        bls12_381_g1_sha_256,
    },
    BbsProofGenRequest,
    BbsProofGenRevealMessageRequest,
    BbsProofVerifyRequest,
    BbsSignRequest,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::BufReader,
    path::Path,
};
use tempfile::Builder as TempFileBuilder;

const CLAIM_HASH_BINDING_DOMAIN: &[u8] = b"c2pa-bbs-claim-hash:";
const DEMO_KEY_INFO: &[u8] = b"c2pa-bbs-demo-key-info";
const DEMO_IKM: [u8; MIN_KEY_GEN_IKM_LENGTH] = *b"c2pa-bbs-demo-static-ikm-seed!!!";
const CLAIM_GENERATOR: &str = "c2pa-bbs-demo/0.1";
const MANIFEST_LABEL: &str = "c2pa-bbs-demo";
const DEMO_LEAF_CERT: &[u8] = include_bytes!("../resources/demo-bbs-leaf.der");
const DEMO_CA_CERT: &[u8] = include_bytes!("../resources/demo-bbs-ca.der");

/// Canonical representation of the claim hash (hex encoded for manifest embedding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimHash(pub String);

/// Proof bytes emitted by the BBS library. Stored as base64 in manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBlob(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAttributes {
    pub issuer: String,
    pub policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenAttributes {
    pub editor_id: String,
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedCredential {
    pub version: String,
    pub issuer_public_key: String,
    pub public_attributes: PublicAttributes,
    pub hidden_attributes: HiddenAttributes,
    pub signature: String,
}

impl IssuedCredential {
    pub fn new(
        issuer_public_key: String,
        public_attributes: PublicAttributes,
        hidden_attributes: HiddenAttributes,
        signature: String,
    ) -> Self {
        Self {
            version: ASSERTION_VERSION.to_string(),
            issuer_public_key,
            public_attributes,
            hidden_attributes,
            signature,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbsSignerProofAssertion {
    #[serde(rename = "type")]
    pub assertion_type: String,
    pub version: String,
    pub public_attributes: PublicAttributes,
    pub claim_hash: ClaimHash,
    pub proof: ProofBlob,
    pub scheme: String,
    /// Base64-encoded issuer BBS public key (BLS12-381 G1, 48 bytes).
    pub issuer_public_key: String,
}

impl BbsSignerProofAssertion {
    pub fn new(
        public_attributes: PublicAttributes,
        claim_hash: ClaimHash,
        proof: ProofBlob,
        issuer_public_key: String,
    ) -> Self {
        Self {
            assertion_type: ASSERTION_TYPE.to_string(),
            version: ASSERTION_VERSION.to_string(),
            public_attributes,
            claim_hash,
            proof,
            scheme: DEFAULT_SCHEME.to_string(),
            issuer_public_key,
        }
    }
}

pub const ASSERTION_TYPE: &str = "bbs-signer-proof";
pub const ASSERTION_VERSION: &str = "0.1";
pub const DEFAULT_SCHEME: &str = "bbs";

pub fn embed_bbs_assertion_into_manifest(asset_path: &str, output_path: &str, assertion: BbsSignerProofAssertion) -> Result<()> {
    let mut manifest = Manifest::new(CLAIM_GENERATOR);
    manifest
        .set_label(MANIFEST_LABEL)
        .set_claim_generator(CLAIM_GENERATOR);

    manifest
        .set_asset_from_path(asset_path)
        .map_err(|err| anyhow!("failed to derive asset metadata: {err}"))?;
    manifest
        .add_labeled_assertion(ASSERTION_TYPE, &assertion)
        .map_err(|err| anyhow!("failed to insert BBS assertion: {err}"))?;

    if let Some(parent) = Path::new(output_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|err| anyhow!("unable to create output directory {parent:?}: {err}"))?;
        }
    }

    let proof_bytes = decode_proof(&assertion.proof)?;
    let pk_bytes = BASE64_STANDARD
        .decode(&assertion.issuer_public_key)
        .map_err(|e| anyhow!("invalid base64 issuer public key: {e}"))?;
    let signer = BbsProofSigner::new(proof_bytes, pk_bytes);

    manifest
        .embed(asset_path, output_path, &signer)
        .map_err(|err| anyhow!("failed to embed manifest: {err}"))?;

    Ok(())
}

pub fn extract_bbs_assertion_from_manifest(asset_path: &str) -> Result<BbsSignerProofAssertion> {
    let reader = Reader::from_file(asset_path)
        .map_err(|err| anyhow!("failed to open manifest store: {err}"))?;
    let manifest = reader
        .active_manifest()
        .ok_or_else(|| anyhow!("asset does not contain an active manifest"))?;

    manifest
        .find_assertion(ASSERTION_TYPE)
        .map_err(|err| anyhow!("missing {ASSERTION_TYPE} assertion: {err}"))
}

/// Result of BBS proof generation: the proof blob and the public key used.
pub struct GeneratedProof {
    pub proof: ProofBlob,
    /// Base64-encoded issuer BBS public key.
    pub issuer_public_key: String,
}

pub fn issue_demo_credential(
    public_attributes: &PublicAttributes,
    hidden_attributes: &HiddenAttributes,
    ) -> Result<IssuedCredential> {
    let key_pair = DemoIssuerKeyPair::new()?;
    let attribute_specs = collect_attribute_messages(public_attributes, hidden_attributes);
    let message_values = signing_messages(&attribute_specs);

    let signature = bls12_381_g1_sha_256::sign(&BbsSignRequest {
        secret_key: &key_pair.secret_key,
        public_key: &key_pair.public_key,
        header: None,
        messages: Some(&message_values),
    })
    .map_err(|err| anyhow!("BBS credential issuance failed: {err:?}"))?;

    Ok(IssuedCredential::new(
        BASE64_STANDARD.encode(key_pair.public_key),
        public_attributes.clone(),
        hidden_attributes.clone(),
        BASE64_STANDARD.encode(signature),
    ))
}

pub fn generate_bbs_proof_from_credential(
    credential: &IssuedCredential,
    claim_hash: &ClaimHash,
) -> Result<GeneratedProof> {
    let attribute_specs = collect_attribute_messages(
        &credential.public_attributes,
        &credential.hidden_attributes,
    );
    let reveal_plan = build_reveal_plan(&attribute_specs);
    let signature_bytes = decode_credential_signature(&credential.signature)?;
    let signature: [u8; 80] = signature_bytes
        .try_into()
        .map_err(|_| anyhow!("credential signature has wrong length"))?;
    let issuer_public_key_bytes = BASE64_STANDARD
        .decode(&credential.issuer_public_key)
        .map_err(|e| anyhow!("invalid base64 issuer public key in credential: {e}"))?;
    let issuer_public_key: [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH] = issuer_public_key_bytes
        .try_into()
        .map_err(|_| anyhow!("issuer public key has wrong length"))?;

    let proof_bytes = bls12_381_g1_sha_256::proof_gen(&BbsProofGenRequest {
        public_key: &issuer_public_key,
        header: None,
        messages: Some(&reveal_plan),
        signature: &signature,
        presentation_header: Some(claim_binding(claim_hash)),
        verify_signature: Some(true),
    })
    .map_err(|err| anyhow!("BBS proof generation failed: {err:?}"))?;

    Ok(GeneratedProof {
        proof: ProofBlob(BASE64_STANDARD.encode(proof_bytes)),
        issuer_public_key: credential.issuer_public_key.clone(),
    })
}

pub fn verify_bbs_proof(
    assertion: &BbsSignerProofAssertion,
    expected_claim_hash: &ClaimHash,
) -> Result<()> {
    if &assertion.claim_hash != expected_claim_hash {
        bail!("claim hash mismatch between proof and asset");
    }

    // Decode the issuer public key from the assertion (base64 → 48 bytes).
    let pk_bytes = BASE64_STANDARD
        .decode(&assertion.issuer_public_key)
        .map_err(|e| anyhow!("invalid base64 issuer public key in assertion: {e}"))?;
    let issuer_public_key: [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH] = pk_bytes
        .try_into()
        .map_err(|_| anyhow!("issuer public key has wrong length"))?;

    let proof_bytes = decode_proof(&assertion.proof)?;
    let revealed_pairs = build_revealed_pairs(&assertion.public_attributes);

    let valid = bls12_381_g1_sha_256::proof_verify(&BbsProofVerifyRequest {
        public_key: &issuer_public_key,
        header: None,
        presentation_header: Some(claim_binding(expected_claim_hash)),
        proof: &proof_bytes,
        messages: Some(&revealed_pairs),
    })
    .map_err(|err| anyhow!("BBS proof verification failed: {err:?}"))?;

    if !valid {
        bail!("invalid BBS signer proof for provided asset");
    }

    Ok(())
}

pub fn compute_claim_hash(asset_path: &str) -> Result<ClaimHash> {
    let file = File::open(asset_path)
        .map_err(|err| anyhow!("failed to open asset {asset_path}: {err}"))?;
    let mut reader = BufReader::new(file);
    let digest = hash_stream_by_alg("sha256", &mut reader, None, false)
        .map_err(|err| anyhow!("failed to compute claim hash: {err}"))?;

    Ok(ClaimHash(hex::encode(digest)))
}

pub fn compute_claim_hash_for_embedded_asset(asset_path: &str) -> Result<ClaimHash> {
    let asset_path = Path::new(asset_path);
    let suffix = asset_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();

    let temp_file = TempFileBuilder::new()
        .prefix("c2pa-bbs-verify-")
        .suffix(&suffix)
        .tempfile()
        .map_err(|err| anyhow!("failed to create temp file for verification: {err}"))?;

    fs::copy(asset_path, temp_file.path())
        .map_err(|err| anyhow!("failed to copy asset for verification: {err}"))?;
    c2pa::jumbf_io::remove_jumbf_from_file(temp_file.path())
        .map_err(|err| anyhow!("failed to remove embedded manifest for verification: {err}"))?;

    compute_claim_hash(&temp_file.path().to_string_lossy())
}

struct DemoIssuerKeyPair {
    secret_key: [u8; BBS_BLS12381G1_SECRET_KEY_LENGTH],
    public_key: [u8; BBS_BLS12381G1_PUBLIC_KEY_LENGTH],
}

impl DemoIssuerKeyPair {
    fn new() -> Result<Self> {
        let raw = KeyPair::new(&DEMO_IKM, DEMO_KEY_INFO)
            .ok_or_else(|| anyhow!("failed to derive deterministic demo key pair"))?;

        Ok(Self {
            secret_key: raw.secret_key.to_bytes(),
            public_key: raw.public_key.to_octets(),
        })
    }
}

struct BbsProofSigner {
    proof: Vec<u8>,
    public_key: Vec<u8>,
}

/// Private-use COSE algorithm value for BBS (BLS12-381, SHA-256).
const BBS_COSE_ALG: i64 = -65535;
/// Critical header label for BBS extension.
const CRIT_LABEL: &str = "c2pa-bbs";

impl BbsProofSigner {
    fn new(proof: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self { proof, public_key }
    }

    /// Build a COSE_Sign1 structure with our custom algorithm.
    fn build_cose(&self, claim_bytes: &[u8]) -> c2pa::Result<Vec<u8>> {
        // Protected header: alg = -65535, crit = ["c2pa-bbs"], x5chain, c2pa-bbs map.
        let certs = self.certs()?;
        let x5chain = if certs.len() == 1 {
            CborValue::Bytes(certs[0].clone())
        } else {
            CborValue::Array(certs.into_iter().map(CborValue::Bytes).collect())
        };

        // c2pa-bbs extension map
        let bbs_ext = CborValue::Map(vec![
            (CborValue::Text("scheme".into()), CborValue::Text("bbs".into())),
            (CborValue::Text("version".into()), CborValue::Text("0.1".into())),
            (CborValue::Text("issuer_public_key".into()), CborValue::Bytes(self.public_key.clone())),
        ]);

        // Build the protected header manually to set the private-use algorithm.
        let protected = Header {
            alg: Some(coset::Algorithm::PrivateUse(BBS_COSE_ALG)),
            rest: vec![
                // x5chain (header param 33)
                (coset::Label::Int(33), x5chain),
                // crit header
                (coset::Label::Text("crit".into()), CborValue::Array(vec![CborValue::Text(CRIT_LABEL.into())])),
                // c2pa-bbs map
                (coset::Label::Text(CRIT_LABEL.into()), bbs_ext),
            ],
            ..Default::default()
        };

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(claim_bytes.to_vec())
            .create_signature(&[], |_| self.proof.clone())
            .build();

        // Remove payload (detached) and serialize as tagged.
        let mut sign1_detached = sign1;
        sign1_detached.payload = None;
        sign1_detached
            .to_tagged_vec()
            .map_err(|e| c2pa::Error::OtherError(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("{e:?}")))))
    }
}

impl Signer for BbsProofSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        // When direct_cose_handling is true, `data` is the claim bytes and we
        // return the full COSE_Sign1 structure.
        let cose = self.build_cose(data)?;
        
        // c2pa-rs expects the signature to be EXACTLY reserve_size bytes (padded).
        if cose.len() > self.reserve_size() {
            return Err(c2pa::Error::OtherError(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("COSE structure {} > reserve_size {}", cose.len(), self.reserve_size()),
            ))));
        }
        
        // Pad to exact reserve_size (c2pa-rs requires this).
        let mut padded = cose;
        padded.resize(self.reserve_size(), 0);
        Ok(padded)
    }

    fn alg(&self) -> SigningAlg {
        // This is ignored when direct_cose_handling() returns true.
        SigningAlg::Ps256
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(vec![DEMO_LEAF_CERT.to_vec(), DEMO_CA_CERT.to_vec()])
    }

    fn reserve_size(&self) -> usize {
        // Account for COSE overhead + proof + certs + headers + padding.
        // The full COSE_Sign1 structure can be quite large with the x5chain.
        self.proof
            .len()
            .saturating_add(DEMO_LEAF_CERT.len())
            .saturating_add(DEMO_CA_CERT.len())
            .saturating_add(self.public_key.len())
            .saturating_add(8192)
    }

    fn direct_cose_handling(&self) -> bool {
        true
    }
}

struct AttributeMessage {
    reveal: bool,
    value: Vec<u8>,
}

impl AttributeMessage {
    fn revealed(value: Vec<u8>) -> Self {
        Self { reveal: true, value }
    }

    fn hidden(value: Vec<u8>) -> Self {
        Self { reveal: false, value }
    }
}

fn collect_attribute_messages(
    public_attributes: &PublicAttributes,
    hidden_attributes: &HiddenAttributes,
) -> Vec<AttributeMessage> {
    vec![
        AttributeMessage::revealed(public_attributes.issuer.clone().into_bytes()),
        AttributeMessage::revealed(public_attributes.policy.clone().into_bytes()),
        AttributeMessage::hidden(hidden_attributes.editor_id.clone().into_bytes()),
        AttributeMessage::hidden(hidden_attributes.device_id.clone().into_bytes()),
    ]
}

fn signing_messages(specs: &[AttributeMessage]) -> Vec<Vec<u8>> {
    specs.iter().map(|entry| entry.value.clone()).collect()
}

fn build_reveal_plan(
    specs: &[AttributeMessage],
) -> Vec<BbsProofGenRevealMessageRequest<Vec<u8>>> {
    specs
        .iter()
        .map(|entry| BbsProofGenRevealMessageRequest {
            reveal: entry.reveal,
            value: entry.value.clone(),
        })
        .collect()
}

fn claim_binding(claim_hash: &ClaimHash) -> Vec<u8> {
    let mut decoded =
        hex::decode(&claim_hash.0).unwrap_or_else(|_| claim_hash.0.as_bytes().to_vec());
    let mut binding =
        Vec::with_capacity(CLAIM_HASH_BINDING_DOMAIN.len() + decoded.len());
    binding.extend_from_slice(CLAIM_HASH_BINDING_DOMAIN);
    binding.append(&mut decoded);
    binding
}

fn build_revealed_pairs(attrs: &PublicAttributes) -> Vec<(usize, Vec<u8>)> {
    vec![
        (0, attrs.issuer.clone().into_bytes()),
        (1, attrs.policy.clone().into_bytes()),
    ]
}

fn decode_proof(proof: &ProofBlob) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(&proof.0)
        .map_err(|err| anyhow!("invalid base64 proof: {err}"))
}

fn decode_credential_signature(signature: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(signature)
        .map_err(|err| anyhow!("invalid base64 credential signature: {err}"))
}
