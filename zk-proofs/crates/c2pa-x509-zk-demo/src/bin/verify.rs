//! X.509 ZK Proof Verifier CLI
//!
//! Verifies that an anonymized C2PA asset contains a valid ZK proof that the
//! original signer's certificate was issued by a CA whose chain (carried in
//! the asset's x5chain) validates against a trust list.
//!
//! Usage:
//!   c2pa-x509-zk-verify --input anon.jpg --trust-list trust-list.pem

use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;

use c2pa_x509_zk_demo::{
    bytes_to_registers, pubkey_registers_from_der,
    circuit_native::{NativeCircuitPaths, NativeProof, verify_proof_native},
    compute_manifest_stripped_asset_digest,
    manifest::read_anonymized_asset,
    spki_key_id, validate_issuing_chain, TrustList,
};

#[derive(Parser, Debug)]
#[command(name = "c2pa-x509-zk-verify")]
#[command(about = "Verify a ZK-anonymized C2PA asset against a trust list")]
struct Args {
    /// Path to the anonymized asset
    #[arg(short, long)]
    input: PathBuf,

    /// Trust list: a PEM bundle of trust anchors, or the C2PA trust list JSON
    #[arg(long)]
    trust_list: PathBuf,

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

    println!("Loading trust list from {:?}...", args.trust_list);
    let trust = TrustList::from_file(&args.trust_list)?;
    println!("  {} trust anchors ({} skipped)", trust.anchors.len(), trust.skipped);

    // Extract ZK assertion and issuing chain (bypassing signature validation)
    println!("\nReading ZK assertion from {:?}...", args.input);
    let (assertion, issuing_chain) = read_anonymized_asset(&args.input)?;

    println!("  Assertion type: {}", assertion.assertion_type);
    println!("  Version: {}", assertion.version);
    println!("  Issuer: {}", assertion.issuer);
    println!("  Issuer Key ID: {}", assertion.issuer_key_id);
    println!("  Claim Hash: {}", assertion.claim_hash);
    println!("  Circuit ID: {}", assertion.circuit_id);
    println!("  Backend: {}", assertion.backend);
    println!("  x5chain: {} certificate(s)", issuing_chain.len());

    // The x5chain carries the issuing chain, issuing CA first. It must chain
    // to the trust list at verification time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let path = match validate_issuing_chain(&issuing_chain, &trust, now) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("\n❌ Issuing chain is not trusted: {e:#}");
            std::process::exit(1);
        }
    };
    // x5chain must be exactly the validated path: nothing after the anchor.
    if path.len() != issuing_chain.len() {
        eprintln!(
            "\n❌ x5chain has {} certificate(s) after the trust anchor; it must hold only the issuing chain",
            issuing_chain.len() - path.len()
        );
        std::process::exit(1);
    }
    let issuing_ca_der = &issuing_chain[0];
    println!("\n✓ Issuing chain validates against the trust list");

    // The assertion's issuer name and key ID must describe that issuing CA.
    let issuing_ca_dn = c2pa_x509_zk_demo::extract_subject_dn(issuing_ca_der)?;
    let issuing_ca_key_id = spki_key_id(issuing_ca_der)?;
    if assertion.issuer != issuing_ca_dn || assertion.issuer_key_id != issuing_ca_key_id {
        eprintln!("\n❌ Assertion does not match the issuing CA in x5chain!");
        eprintln!("   x5chain issuing CA: {issuing_ca_dn} (key ID {issuing_ca_key_id})");
        eprintln!("   Assertion:          {} (key ID {})", assertion.issuer, assertion.issuer_key_id);
        std::process::exit(1);
    }
    println!("✓ Assertion issuer matches the issuing CA");

    let expected_claim_hash = hex::encode(compute_manifest_stripped_asset_digest(&args.input)?);
    if assertion.claim_hash != expected_claim_hash {
        eprintln!("\n❌ Asset binding digest mismatch!");
        eprintln!("   Expected (from manifest-stripped asset): {expected_claim_hash}");
        eprintln!("   Got (from assertion):                   {}", assertion.claim_hash);
        std::process::exit(1);
    }
    println!("✓ Assertion digest matches manifest-stripped asset");

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
        std::process::exit(2);
    }

    // Verify the ZK proof
    println!("\nVerifying ZK proof...");

    let native_paths = NativeCircuitPaths::default_for_circuit(
        &args.circuits_dir,
        "x509_issue_and_possession",
    );

    // Verification needs only the local, trusted verifying key: never keys
    // chosen from anything the asset says.
    if !native_paths.can_verify() {
        bail!(
            "No verifying key at {:?}. Run c2pa-x509-zk-setup first.",
            native_paths.verifying_key
        );
    }

    // Artifact identifiers are diagnostics only: they help explain a failure,
    // but the Groth16 verification below decides validity.
    match (&assertion.circuit_r1cs_sha256, &assertion.verifying_key_sha256) {
        (Some(circuit), Some(vk)) => {
            let local_vk = c2pa_x509_zk_demo::file_sha256(&native_paths.verifying_key)?;
            let local_circuit = native_paths.read_build_manifest()?.map(|m| m.r1cs_sha256);
            if *vk != local_vk || local_circuit.as_ref().is_some_and(|c| c != circuit) {
                println!("⚠️  This proof was made with a different circuit or keys than the local ones:");
                println!("   asset: circuit {circuit}, verifying key {vk}");
                println!(
                    "   local: circuit {}, verifying key {local_vk}",
                    local_circuit.as_deref().unwrap_or("(no build manifest)")
                );
                println!("   Verification below will most likely fail.");
            } else {
                println!("✓ Proof was made for the local circuit and verifying key");
            }
        }
        _ => println!(
            "  (assertion version {} records no circuit or key identifiers)",
            assertion.version
        ),
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
    //   [12.. 17] claimHash[0..5]  — manifest-stripped asset digest
    //   [18]      photoTimestamp   — Unix anonymization-time timestamp (public, informational)
    // -------------------------------------------------------------------------
    const K: usize = 6;

    if proof.public_inputs.len() < 2 * K + K + 1 {
        bail!(
            "proof has {} public inputs, expected at least {}",
            proof.public_inputs.len(),
            2 * K + K + 1
        );
    }

    // Reconstruct expected caPubKeyX/Y registers from the issuing CA, whose
    // chain was validated above.
    let (expected_ca_x, expected_ca_y) =
        pubkey_registers_from_der(issuing_ca_der)
            .map_err(|e| anyhow::anyhow!("failed to extract CA public key registers: {e}"))?;

    for (i, expected) in expected_ca_x.iter().enumerate() {
        if &proof.public_inputs[i] != expected {
            eprintln!("\n❌ Public signal mismatch: caPubKeyX[{i}]");
            eprintln!("   Expected (from issuing CA):  {expected}");
            eprintln!("   Embedded in proof:                {}", proof.public_inputs[i]);
            eprintln!("\n   The proof was generated for a DIFFERENT CA public key.");
            std::process::exit(1);
        }
    }
    for (i, expected) in expected_ca_y.iter().enumerate() {
        if &proof.public_inputs[K + i] != expected {
            eprintln!("\n❌ Public signal mismatch: caPubKeyY[{i}]");
            eprintln!("   Expected (from issuing CA):  {expected}");
            eprintln!("   Embedded in proof:                {}", proof.public_inputs[K + i]);
            eprintln!("\n   The proof was generated for a DIFFERENT CA public key.");
            std::process::exit(1);
        }
    }
    println!("✓ Proof CA public key matches the issuing CA");

    // Reconstruct expected claimHash registers from the recomputed asset digest.
    let claim_hash_bytes: [u8; 32] = hex::decode(&expected_claim_hash)
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
            println!("   The asset was anonymized using a certificate issued by a CA that chains to the trust list.");
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
