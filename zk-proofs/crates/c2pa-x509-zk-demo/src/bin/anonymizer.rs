//! X.509 ZK Anonymizer CLI
//!
//! Takes a standard X.509-signed C2PA asset and replaces the signature
//! with a ZK proof that the signer's cert was issued by a trusted CA.
//!
//! Usage:
//!   c2pa-x509-zk-anonymizer --input signed.jpg --output anon.jpg --ca root.pem

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
#[command(name = "c2pa-x509-zk-anonymizer")]
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

    /// Path to the original signer certificate (PEM or DER).
    /// c2pa-rs may re-encode the certificate when storing it in the manifest
    /// (e.g. adding NULL parameters to AlgorithmIdentifiers), changing the
    /// TBS bytes and invalidating the CA signature for the ZK proof.
    /// Passing the original file ensures the circuit sees the exact DER the
    /// CA signed.  Required when c2pa-rs alters the cert during storage.
    #[arg(long)]
    cert: Option<PathBuf>,

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

    println!("=== C2PA X.509 ZK Anonymizer ===\n");

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
    println!("  Asset binding digest: {} bytes", manifest_data.claim_hash.len());

    // If the caller supplied the original cert file, override the extracted
    // cert bytes.  c2pa-rs can re-encode a PEM cert when embedding it in the
    // COSE structure (e.g. adding NULL parameters to AlgorithmIdentifiers),
    // which changes the TBS bytes and invalidates the CA signature check
    // inside the ZK circuit.  Using the on-disk bytes guarantees exactness.
    let mut manifest_data = manifest_data;
    if let Some(cert_path) = &args.cert {
        let cert_bytes = if cert_path.extension().map(|e| e == "pem").unwrap_or(false) {
            // PEM: decode to DER
            let pem = std::fs::read_to_string(cert_path)
                .map_err(|e| anyhow!("failed to read cert: {e}"))?;
            let b64: String = pem
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(b64)
                .map_err(|e| anyhow!("invalid base64 in cert PEM: {e}"))?   
        } else {
            std::fs::read(cert_path)
                .map_err(|e| anyhow!("failed to read cert: {e}"))?   
        };
        let orig_len = manifest_data.leaf_cert_der.len();
        manifest_data.leaf_cert_der = cert_bytes;
        eprintln!("[info] Overriding manifest cert ({orig_len}B) with {} from {:?}",
            manifest_data.leaf_cert_der.len(), cert_path);
    }

    // Extract issuer DN from leaf certificate
    let issuer_dn = extract_issuer_dn(&manifest_data.leaf_cert_der)?;
    println!("  Issuer: {issuer_dn}");

    // Compute CA key ID
    let ca_key_id = compute_key_id(&ca_params.ca_cert_der);
    println!("  CA Key ID: {ca_key_id}");

    // Check if native setup is complete (use x509_issue_and_possession circuit)
    let native_paths = NativeCircuitPaths::default_for_circuit(
        &args.circuits_dir,
        "x509_issue_and_possession",
    );

    // Use placeholder mode if explicitly requested or if setup is not complete
    let use_placeholder = args.placeholder || !native_paths.setup_complete();

    if use_placeholder {
        if !native_paths.setup_complete() {
            eprintln!("\n⚠️  Native ZK setup not complete!");
            eprintln!("   Run the following from the zk-proofs/ directory:");
            eprintln!("   1. npm install --prefix circuits");
            eprintln!("   2. mkdir -p circuits/build");
            eprintln!("   3. circom circuits/x509_issue_and_possession.circom \\");
            eprintln!("        --r1cs --wasm --sym -l circuits -l circuits/node_modules -o circuits/build/");
            eprintln!("   4. cargo run --release --bin c2pa-x509-zk-setup -- --circuits-dir circuits");
        }
        eprintln!("\n   Creating a placeholder assertion...\n");

        let cert_chain_der = std::iter::once(manifest_data.leaf_cert_der.clone())
            .chain(manifest_data.ca_certs_der.iter().cloned())
            .collect();

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
        match rewrite_manifest_with_zk_proof(&args.input, &args.output, assertion, cert_chain_der) {
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

        // Convert to circuit format — parses the leaf cert internally to
        // extract tbsCertHash, certSig, subjectPubkey, and validity dates.
        let circuit_inputs = circuit::proof_inputs_to_circuit(&proof_inputs)?;

        println!("Generating native ZK proof...");
        let proof = circuit_native::generate_proof_native(&circuit_inputs, &native_paths)?;
        let proof_base64 = proof.to_base64()?;

        let assertion = X509ZkSignerProofAssertion::new(
            issuer_dn,
            ca_key_id,
            hex::encode(&manifest_data.claim_hash),
            proof_base64,
        );

        let cert_chain_der = std::iter::once(manifest_data.leaf_cert_der.clone())
            .chain(manifest_data.ca_certs_der.iter().cloned())
            .collect();

        println!("Rewriting manifest with ZK proof...");
        rewrite_manifest_with_zk_proof(&args.input, &args.output, assertion, cert_chain_der)?;

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

