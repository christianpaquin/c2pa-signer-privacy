//! X.509 ZK Proof Verifier CLI
//!
//! Verifies that an anonymized C2PA asset contains a valid ZK proof
//! that the original signer's certificate was issued by a trusted CA.
//!
//! Usage:
//!   c2pa-x509-zk-verify --input anon.jpg --ca root.pem

use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;

use c2pa_x509_zk_demo::{
    bytes_to_registers, pubkey_registers_from_der,
    circuit_native::{NativeCircuitPaths, NativeProof, verify_proof_native},
    compute_key_id,
    types::TrustedCaParams,
    X509ZkSignerProofAssertion, ASSERTION_TYPE,
};

#[derive(Parser, Debug)]
#[command(name = "c2pa-x509-zk-verify")]
#[command(about = "Verify a ZK-anonymized C2PA asset against a trusted CA")]
struct Args {
    /// Path to the anonymized asset
    #[arg(short, long)]
    input: PathBuf,

    /// Path to the trusted CA certificate (PEM or DER)
    #[arg(long)]
    ca: PathBuf,

    /// Expected issuer DN (optional, for additional validation)
    #[arg(long)]
    issuer: Option<String>,

    /// Path to the Circom circuits build directory
    #[arg(long, default_value = "circuits")]
    circuits_dir: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("=== C2PA X.509 ZK Proof Verifier ===\n");

    // Load trusted CA certificate
    println!("Loading CA certificate from {:?}...", args.ca);
    let ca_params = if args.ca.extension().map(|e| e == "pem").unwrap_or(false) {
        TrustedCaParams::from_pem_file(&args.ca)?
    } else {
        TrustedCaParams::from_der_file(&args.ca)?
    };

    // Compute expected CA key ID
    let expected_key_id = compute_key_id(&ca_params.ca_cert_der);
    println!("  Expected CA Key ID: {expected_key_id}");

    // Extract ZK assertion from the asset (bypassing signature validation)
    println!("\nReading ZK assertion from {:?}...", args.input);
    let assertion = extract_zk_assertion_no_verify(&args.input)?;

    println!("  Assertion type: {}", assertion.assertion_type);
    println!("  Version: {}", assertion.version);
    println!("  Issuer: {}", assertion.issuer);
    println!("  Issuer Key ID: {}", assertion.issuer_key_id);
    println!("  Claim Hash: {}", assertion.claim_hash);
    println!("  Circuit ID: {}", assertion.circuit_id);
    println!("  Backend: {}", assertion.backend);

    // Verify issuer key ID matches trusted CA
    if assertion.issuer_key_id != expected_key_id {
        eprintln!("\n❌ Issuer key ID mismatch!");
        eprintln!("   Expected: {expected_key_id}");
        eprintln!("   Got: {}", assertion.issuer_key_id);
        std::process::exit(1);
    }
    println!("\n✓ Issuer key ID matches trusted CA");

    // Verify expected issuer if provided
    if let Some(expected_issuer) = &args.issuer {
        if &assertion.issuer != expected_issuer {
            eprintln!("\n❌ Issuer DN mismatch!");
            eprintln!("   Expected: {expected_issuer}");
            eprintln!("   Got: {}", assertion.issuer);
            std::process::exit(1);
        }
        println!("✓ Issuer DN matches expected value");
    }

    // Check if this is a placeholder proof
    if assertion.proof.starts_with("PLACEHOLDER") {
        eprintln!("\n⚠️  Proof is a placeholder - circuits not built yet");
        eprintln!("   Build circuits to generate real ZK proofs.");
        std::process::exit(0);
    }

    // Verify the ZK proof
    println!("\nVerifying ZK proof...");

    let native_paths = NativeCircuitPaths::default_for_circuit(
        &args.circuits_dir,
        "x509_issue_and_possession",
    );

    if !native_paths.setup_complete() {
        bail!(
            "Native setup not complete. Run c2pa-x509-zk-setup first.",
        );
    }

    let proof = NativeProof::from_base64(&assertion.proof)?;

    // -------------------------------------------------------------------------
    // Public signal binding check
    //
    // A valid Groth16 proof only guarantees that the prover knew a witness
    // satisfying the circuit for SOME public inputs — not necessarily the ones
    // we care about.  We must explicitly verify that the public inputs embedded
    // in the proof match (a) the CA we trust and (b) the claim hash recorded in
    // the assertion.
    //
    // Circuit public-input layout (k = 6 registers, indices 0-based):
    //   [0 .. 5]  caPubKeyX[0..5]  — CA public key X, LSB register first
    //   [6 .. 11] caPubKeyY[0..5]  — CA public key Y
    //   [12.. 17] claimHash[0..5]  — C2PA claim hash
    //   [18]      photoTimestamp   — Unix photo timestamp (public, informational)
    // -------------------------------------------------------------------------
    const K: usize = 6;

    if proof.public_inputs.len() < 2 * K + K + 1 {
        bail!(
            "proof has {} public inputs, expected at least {}",
            proof.public_inputs.len(),
            2 * K + K + 1
        );
    }

    // Reconstruct expected caPubKeyX/Y registers from the trusted CA cert.
    let (expected_ca_x, expected_ca_y) =
        pubkey_registers_from_der(&ca_params.ca_cert_der)
            .map_err(|e| anyhow::anyhow!("failed to extract CA public key registers: {e}"))?;

    for (i, expected) in expected_ca_x.iter().enumerate() {
        if &proof.public_inputs[i] != expected {
            eprintln!("\n❌ Public signal mismatch: caPubKeyX[{i}]");
            eprintln!("   Expected (from trusted CA cert):  {expected}");
            eprintln!("   Embedded in proof:                {}", proof.public_inputs[i]);
            eprintln!("\n   The proof was generated for a DIFFERENT CA public key.");
            std::process::exit(1);
        }
    }
    for (i, expected) in expected_ca_y.iter().enumerate() {
        if &proof.public_inputs[K + i] != expected {
            eprintln!("\n❌ Public signal mismatch: caPubKeyY[{i}]");
            eprintln!("   Expected (from trusted CA cert):  {expected}");
            eprintln!("   Embedded in proof:                {}", proof.public_inputs[K + i]);
            eprintln!("\n   The proof was generated for a DIFFERENT CA public key.");
            std::process::exit(1);
        }
    }
    println!("✓ Proof CA public key matches trusted CA");

    // Reconstruct expected claimHash registers from the assertion's claim_hash.
    let claim_hash_bytes: [u8; 32] = hex::decode(&assertion.claim_hash)
        .map_err(|_| anyhow::anyhow!("assertion.claim_hash is not valid hex"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("assertion.claim_hash is not 32 bytes"))?;
    let expected_claim_hash = bytes_to_registers(&claim_hash_bytes);

    for (i, expected) in expected_claim_hash.iter().enumerate() {
        if &proof.public_inputs[2 * K + i] != expected {
            eprintln!("\n❌ Public signal mismatch: claimHash[{i}]");
            eprintln!("   Expected (from assertion):  {expected}");
            eprintln!("   Embedded in proof:          {}", proof.public_inputs[2 * K + i]);
            eprintln!("\n   The proof's embedded claim hash does not match the assertion.");
            std::process::exit(1);
        }
    }
    println!("✓ Proof claim hash matches assertion");

    match verify_proof_native(&proof, &native_paths) {
        Ok(true) => {
            println!("\n✅ ZK proof verified successfully!");
            println!("   Issuer: {}", assertion.issuer);
            println!("   The asset was signed by a certificate issued by the trusted CA.");
        }
        Ok(false) => {
            eprintln!("\n❌ ZK proof verification failed!");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("\n❌ Error verifying proof: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Extract ZK assertion without verifying the COSE signature.
/// 
/// For ZK-anonymized manifests, the COSE signature uses a private-use algorithm
/// that c2pa-rs doesn't recognize. We need to disable signature verification
/// and directly read the assertion.
fn extract_zk_assertion_no_verify(path: &PathBuf) -> Result<X509ZkSignerProofAssertion> {
    use c2pa::{Reader, settings};
    
    // Disable signature verification for custom algorithms
    let settings_json = r#"{
        "verify": {
            "verify_after_reading": false
        }
    }"#;
    settings::load_settings_from_str(settings_json, "json")
        .map_err(|e| anyhow::anyhow!("failed to load settings: {e}"))?;
    
    let reader = Reader::from_file(path)
        .map_err(|e| anyhow::anyhow!("failed to read manifest: {e}"))?;
    
    let manifest = reader.active_manifest()
        .ok_or_else(|| anyhow::anyhow!("no active manifest in asset"))?;
    
    manifest.find_assertion(ASSERTION_TYPE)
        .map_err(|e| anyhow::anyhow!("missing {ASSERTION_TYPE} assertion: {e}"))
}
