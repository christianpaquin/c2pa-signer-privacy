//! X.509 ZK Anonymizing Editor CLI
//!
//! Takes a standard X.509-signed C2PA asset and replaces the signature
//! with a ZK proof that the signer's cert was issued by a trusted CA.
//!
//! Usage:
//!   c2pa-x509-zk-editor --input signed.jpg --output anon.jpg --ca root.pem

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::PathBuf;

use c2pa_x509_zk_demo::{
    circuit,
    circuit_native::{self, NativeCircuitPaths},
    manifest::{extract_manifest_data, rewrite_manifest_with_zk_proof},
    types::TrustedCaParams,
    X509ZkSignerProofAssertion,
    extract_issuer_dn, compute_key_id,
};

#[derive(Parser, Debug)]
#[command(name = "c2pa-x509-zk-editor")]
#[command(about = "Anonymize a C2PA asset by replacing X.509 signature with ZK proof")]
struct Args {
    /// Path to the input asset (must have a valid C2PA X.509 signature)
    #[arg(short, long)]
    input: PathBuf,

    /// Path for the anonymized output asset
    #[arg(short, long)]
    output: PathBuf,

    /// Path to the trusted CA certificate (PEM or DER)
    #[arg(long)]
    ca: PathBuf,

    /// Path to the signer's private key (for generating proof-of-possession)
    /// In production, this would be done on the signer's secure device
    #[arg(long)]
    signer_key: Option<PathBuf>,

    /// Path to the Circom circuits build directory
    #[arg(long, default_value = "circuits")]
    circuits_dir: PathBuf,
    
    /// Use placeholder proof (for testing without ZK setup)
    #[arg(long)]
    placeholder: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("=== C2PA X.509 ZK Anonymizing Editor ===\n");

    // Load trusted CA certificate
    println!("Loading CA certificate from {:?}...", args.ca);
    let ca_params = if args.ca.extension().map(|e| e == "pem").unwrap_or(false) {
        TrustedCaParams::from_pem_file(&args.ca)?
    } else {
        TrustedCaParams::from_der_file(&args.ca)?
    };

    // Extract manifest data from the signed asset
    println!("Reading manifest from {:?}...", args.input);
    let manifest_data = extract_manifest_data(&args.input)?;

    println!("  Leaf certificate: {} bytes", manifest_data.leaf_cert_der.len());
    println!("  CA certificates: {}", manifest_data.ca_certs_der.len());
    println!("  Claim hash: {} bytes", manifest_data.claim_hash.len());

    // Extract issuer DN from leaf certificate
    let issuer_dn = extract_issuer_dn(&manifest_data.leaf_cert_der)?;
    println!("  Issuer: {issuer_dn}");

    // Compute CA key ID
    let ca_key_id = compute_key_id(&ca_params.ca_cert_der);
    println!("  CA Key ID: {ca_key_id}");

    // Check if native setup is complete (use c2pa_signer_proof circuit)
    let native_paths = NativeCircuitPaths::default_for_circuit(
        &args.circuits_dir,
        "c2pa_signer_proof",
    );

    // Use placeholder mode if explicitly requested or if setup is not complete
    let use_placeholder = args.placeholder || !native_paths.setup_complete();

    if use_placeholder {
        if !native_paths.setup_complete() {
            eprintln!("\n⚠️  Native ZK setup not complete!");
            eprintln!("   Run the following to build circuits and setup:");
            eprintln!("   cd circuits && ./build.sh");
            eprintln!("   cargo run --release --bin c2pa-x509-zk-setup");
        }
        eprintln!("\n   Creating a placeholder assertion...\n");

        // Create placeholder assertion for testing the flow
        let assertion = X509ZkSignerProofAssertion::new(
            issuer_dn,
            ca_key_id,
            hex::encode(&manifest_data.claim_hash),
            "PLACEHOLDER_PROOF".to_string(),
        );

        println!("Assertion preview:");
        println!("{}", serde_json::to_string_pretty(&assertion)?);

        // Try to rewrite manifest (will fail until custom signer is implemented)
        match rewrite_manifest_with_zk_proof(&args.input, &args.output, assertion) {
            Ok(()) => println!("\n✅ Anonymized asset written to {:?}", args.output),
            Err(e) => {
                eprintln!("\n❌ Manifest rewrite not yet implemented: {e}");
                eprintln!("   This requires custom COSE handling similar to Strategy 1.");
                std::process::exit(1);
            }
        }
    } else {
        // Full native ZK proof generation path
        let signer_key_path = args.signer_key
            .ok_or_else(|| anyhow!("--signer-key required when setup is complete"))?;
        
        let signer_key_pem = std::fs::read_to_string(&signer_key_path)?;
        let signer_key = parse_ec_private_key_pem(&signer_key_pem)?;

        println!("\nPreparing circuit inputs...");
        let proof_inputs = circuit::prepare_inputs(
            &manifest_data,
            &signer_key,
            &ca_params.ca_cert_der,
        )?;
        
        // Extract signer's public key from certificate
        let signer_pubkey = extract_signer_pubkey(&manifest_data.leaf_cert_der)?;
        
        // Convert to circuit format
        let circuit_inputs = circuit::proof_inputs_to_circuit(
            &proof_inputs,
            &issuer_dn,
            &signer_pubkey,
        )?;

        println!("Generating native ZK proof (this may take ~30 seconds)...");
        let proof = circuit_native::generate_proof_native(&circuit_inputs, &native_paths)?;
        let proof_base64 = proof.to_base64()?;

        let assertion = X509ZkSignerProofAssertion::new(
            issuer_dn,
            ca_key_id,
            hex::encode(&manifest_data.claim_hash),
            proof_base64,
        );

        println!("Rewriting manifest with ZK proof...");
        rewrite_manifest_with_zk_proof(&args.input, &args.output, assertion)?;

        println!("\n✅ Anonymized asset written to {:?}", args.output);
    }

    Ok(())
}

/// Parse a PEM-encoded EC private key
fn parse_ec_private_key_pem(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    
    let start = pem.find("-----BEGIN EC PRIVATE KEY-----")
        .or_else(|| pem.find("-----BEGIN PRIVATE KEY-----"))
        .ok_or_else(|| anyhow!("invalid PEM: missing start marker"))?;
    
    let end_marker = if pem.contains("-----BEGIN EC PRIVATE KEY-----") {
        "-----END EC PRIVATE KEY-----"
    } else {
        "-----END PRIVATE KEY-----"
    };
    
    let end = pem.find(end_marker)
        .ok_or_else(|| anyhow!("invalid PEM: missing end marker"))?;
    
    let start_marker_len = if pem.contains("-----BEGIN EC PRIVATE KEY-----") {
        "-----BEGIN EC PRIVATE KEY-----".len()
    } else {
        "-----BEGIN PRIVATE KEY-----".len()
    };
    
    let base64_content: String = pem[start + start_marker_len..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    
    base64::engine::general_purpose::STANDARD
        .decode(&base64_content)
        .map_err(|e| anyhow!("invalid base64 in PEM: {e}"))
}

/// Extract signer's public key from certificate
fn extract_signer_pubkey(cert_der: &[u8]) -> Result<circuit::PublicKeyComponents> {
    use der::Decode;
    use x509_cert::Certificate;
    use p256::PublicKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("failed to parse certificate: {e}"))?;
    
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pk_bytes = spki.subject_public_key.as_bytes()
        .ok_or_else(|| anyhow!("public key not byte-aligned"))?;
    
    let public_key = PublicKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| anyhow!("failed to parse P-256 public key: {e}"))?;
    
    let point = public_key.to_encoded_point(false);
    let x = point.x().ok_or_else(|| anyhow!("missing x coordinate"))?;
    let y = point.y().ok_or_else(|| anyhow!("missing y coordinate"))?;
    
    Ok(circuit::PublicKeyComponents {
        x: hex::encode(x),
        y: hex::encode(y),
    })
}
