//! Standard X.509/ECDSA Signer CLI
//!
//! Creates a standard C2PA signed asset using P-256 ECDSA.
//! This produces the input for the anonymizer.
//!
//! Usage:
//!   c2pa-x509-zk-sign --input unsigned.png --output signed.png \
//!       --cert signer.pem --key signer.key --ca issuing-ca.pem \
//!       [--tsa-cert tsa.pem --tsa-key tsa.key]
//!
//! With a TSA certificate and key (for example from
//! `generate-test-pki.sh --mirror`), the signature is time-stamped by a local
//! test TSA and the token stored as `sigTst2`, as on real devices.

use anyhow::{anyhow, Result};
use c2pa::{create_signer, Signer, SigningAlg};
use c2pa_x509_zk_demo::local_tsa::{LocalTsa, TimeStampingSigner};
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

    /// Issuing CA certificate(s) (PEM), included after the signer certificate
    /// in x5chain. The root is not included, per the C2PA specification.
    #[arg(long)]
    ca: PathBuf,

    /// Test TSA certificate (PEM): time-stamp the signature with a local TSA
    #[arg(long, requires = "tsa_key")]
    tsa_cert: Option<PathBuf>,

    /// Test TSA private key (PEM)
    #[arg(long, requires = "tsa_cert")]
    tsa_key: Option<PathBuf>,

    /// C2PA claim version: 2 (current; time stamp in `sigTst2`) or 1 (legacy;
    /// time stamp in `sigTst`, as in older real assets)
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=2))]
    claim_version: u8,
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

    // x5chain: signer + issuing CA(s)
    let cert_chain = format!("{}\n{}", signer_cert_pem.trim(), ca_cert_pem.trim());

    println!("Loaded signer cert from {:?}", args.cert);
    println!("Loaded CA cert from {:?}", args.ca);

    // Create c2pa signer with ES256 (P-256 ECDSA)
    let mut signer: Box<dyn Signer> = create_signer::from_keys(
        cert_chain.as_bytes(),
        signer_key_pem.as_bytes(),
        SigningAlg::Es256,
        None, // no network TSA
    )
    .map_err(|e| anyhow!("failed to create signer: {e}"))?;
    if let (Some(cert), Some(key)) = (args.tsa_cert, args.tsa_key) {
        println!("Time-stamping with the local TSA {cert:?}");
        signer = Box::new(TimeStampingSigner::new(signer, LocalTsa { cert, key }));
    }

    // Build manifest using Builder API
    // A c2pa.created action, as C2PA requires of a new asset's first manifest
    // and real device claims carry.
    let definition = serde_json::json!({
        "claim_version": args.claim_version,
        "claim_generator_info": [{ "name": CLAIM_GENERATOR, "version": "0.1" }],
        "assertions": [{
            "label": "c2pa.actions.v2",
            "data": { "actions": [{
                "action": "c2pa.created",
                "description": "Created by the c2pa-x509-zk test signer.",
                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
            }]}
        }]
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
