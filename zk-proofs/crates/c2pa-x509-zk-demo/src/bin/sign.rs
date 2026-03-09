//! Standard X.509/ECDSA Signer CLI
//!
//! Creates a standard C2PA signed asset using P-256 ECDSA.
//! This produces the input for the anonymizer.
//!
//! Usage:
//!   c2pa-x509-zk-sign --input unsigned.png --output signed.png \
//!       --cert signer.pem --key signer-key.pem --ca ca.pem

use anyhow::{anyhow, Result};
use c2pa::{create_signer, SigningAlg};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "c2pa-x509-zk-sign")]
#[command(about = "Sign a C2PA asset with standard X.509/ECDSA P-256")]
struct Args {
    /// Path to the input asset (unsigned)
    #[arg(short, long)]
    input: PathBuf,

    /// Path for the signed output asset
    #[arg(short, long)]
    output: PathBuf,

    /// Path to the signer certificate (PEM)
    #[arg(long)]
    cert: PathBuf,

    /// Path to the signer private key (PEM)
    #[arg(long)]
    key: PathBuf,

    /// Path to the CA certificate (PEM) - included in chain
    #[arg(long)]
    ca: PathBuf,
}

const CLAIM_GENERATOR: &str = "c2pa-x509-zk-demo/0.1";

fn main() -> Result<()> {
    let args = Args::parse();

    println!("=== C2PA Standard X.509/ECDSA Signer ===\n");

    // Load certificates and key
    let signer_cert_pem = fs::read_to_string(&args.cert)
        .map_err(|e| anyhow!("failed to read signer cert: {e}"))?;
    let signer_key_pem = fs::read_to_string(&args.key)
        .map_err(|e| anyhow!("failed to read signer key: {e}"))?;
    let ca_cert_pem = fs::read_to_string(&args.ca)
        .map_err(|e| anyhow!("failed to read CA cert: {e}"))?;

    // Concatenate cert chain: signer + CA
    let cert_chain = format!("{}\n{}", signer_cert_pem.trim(), ca_cert_pem.trim());

    println!("Loaded signer cert from {:?}", args.cert);
    println!("Loaded CA cert from {:?}", args.ca);

    // Create c2pa signer with ES256 (P-256 ECDSA)
    let signer = create_signer::from_keys(
        cert_chain.as_bytes(),
        signer_key_pem.as_bytes(),
        SigningAlg::Es256,
        None, // no TSA
    )
    .map_err(|e| anyhow!("failed to create signer: {e}"))?;

    // Build manifest using Builder API
    let definition = serde_json::json!({
        "claim_generator_info": [{ "name": CLAIM_GENERATOR, "version": "0.1" }]
    });
    let mut builder = c2pa::Builder::from_json(&definition.to_string())
        .map_err(|e| anyhow!("failed to create builder: {e}"))?;

    // Embed manifest
    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    builder
        .sign_file(signer.as_ref(), &args.input, &args.output)
        .map_err(|e| anyhow!("failed to embed manifest: {e}"))?;

    println!("\n✅ Signed asset written to {:?}", args.output);
    println!("   Algorithm: ES256 (P-256 ECDSA)");

    Ok(())
}
