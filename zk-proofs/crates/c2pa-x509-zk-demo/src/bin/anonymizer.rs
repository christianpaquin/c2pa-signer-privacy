//! X.509 ZK Anonymizer CLI
//!
//! Takes a standard X.509-signed C2PA asset and replaces the signature
//! with a ZK proof that the signer's cert was issued by a trusted CA.
//!
//! Usage:
//!   c2pa-x509-zk-anonymizer --input signed.jpg --output anon.jpg --trust-list trust-list.pem
//!   c2pa-x509-zk-anonymizer --third-party --keys gnark-keys/ --input signed.jpg --output anon.jpg \
//!       --trust-list trust-list.pem
//!
//! Third-party mode (roadmap E2b; --third-party) proves the original signature
//! and replaces it in place; it is the current mode. Without it, the anonymizer
//! runs the frozen V0 baseline (signer-side: re-signs with the signer's key),
//! kept so its results can be reproduced (zk-proofs/HISTORY.md).

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::PathBuf;

use c2pa_x509_zk_demo::{
    circuit,
    circuit_native::{self, NativeCircuitPaths},
    manifest::{extract_manifest_data, rewrite_manifest_with_zk_proof},
    X509ZkSignerProofAssertion,
    extract_issuer_dn, issuing_path_for, spki_key_id, TrustList,
};

#[derive(Parser, Debug)]
#[command(name = "c2pa-x509-zk-anonymizer")]
#[command(about = "Anonymize a C2PA asset by replacing its X.509 signature with a ZK proof (--third-party: the current mode; otherwise the frozen V0 baseline)")]
struct Args {
    /// Path to the input asset (must have a valid C2PA X.509 signature)
    #[arg(short, long)]
    input: PathBuf,

    /// Path for the anonymized output asset
    #[arg(short, long)]
    output: PathBuf,

    /// Trust list: a PEM bundle of trust anchors, or the C2PA trust list JSON
    #[arg(long)]
    trust_list: PathBuf,

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

    /// Third-party mode (E2b): prove the original signature in gnark and
    /// replace it in place; no private key needed (requires --keys)
    #[arg(long)]
    third_party: bool,

    /// Key directory from `c2pa-zk-gnark setup` (third-party mode)
    #[arg(long)]
    keys: Option<PathBuf>,

    /// The c2pa-zk-gnark CLI (default: c2pa-zk-gnark next to the target directory)
    #[arg(long)]
    gnark: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.third_party {
        return third_party(&args);
    }

    println!("=== C2PA X.509 ZK Anonymizer ===\n");

    println!("Loading trust list from {:?}...", args.trust_list);
    let trust = TrustList::from_file(&args.trust_list)?;
    println!("  {} trust anchors ({} skipped)", trust.anchors.len(), trust.skipped);

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
    // The signer's key, as it appears in the signed asset. Used below to make
    // sure no certificate for that key is embedded in the output.
    let signer_key_id = spki_key_id(&manifest_data.leaf_cert_der)?;
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

    // The issuing path to embed in x5chain: from the signed asset's
    // intermediates, or the trust anchor that issued the signer certificate,
    // validated now rather than after a ~10 minute proof. Only the validated
    // path is embedded: certificates after the trust anchor are not part of
    // it and could be anything, including the signer's own.
    let issuing_chain = issuing_path_for(
        &manifest_data.leaf_cert_der,
        &manifest_data.ca_certs_der,
        &trust,
        manifest_data.photo_timestamp,
    )?;
    // Both the signed asset's signer certificate and a --cert override.
    let signer_keys = [signer_key_id, spki_key_id(&manifest_data.leaf_cert_der)?];
    for cert in &issuing_chain {
        if signer_keys.contains(&spki_key_id(cert)?) {
            anyhow::bail!("refusing to embed a certificate for the signer's key in x5chain");
        }
    }
    let issuing_ca_der = issuing_chain[0].clone();
    println!("  Issuing chain: {} certificate(s), validated against the trust list", issuing_chain.len());

    let issuer_dn = extract_issuer_dn(&manifest_data.leaf_cert_der)?;
    println!("  Issuer: {issuer_dn}");
    let ca_key_id = spki_key_id(&issuing_ca_der)?;
    println!("  Issuing CA key ID: {ca_key_id}");

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
        match rewrite_manifest_with_zk_proof(&args.input, &args.output, assertion, issuing_chain) {
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
        
        // Keys from an older circuit would yield a proof that never verifies,
        // after the full (~10 minute) proving run.
        if !native_paths.keys_match_circuit()? {
            anyhow::bail!(
                "proving key does not match the compiled circuit; re-run \
                 `c2pa-x509-zk-setup --circuits-dir {} --force`",
                args.circuits_dir.display()
            );
        }

        let signer_key_pem = std::fs::read_to_string(&signer_key_path)?;
        let signer_key = parse_ec_private_key_pem(&signer_key_pem)?;

        println!("\nPreparing circuit inputs...");
        let proof_inputs = circuit::prepare_inputs(
            &manifest_data,
            &signer_key,
            &issuing_ca_der,
        )?;

        // Convert to circuit format — parses the leaf cert internally to
        // extract tbsCertHash, certSig, subjectPubkey, and validity dates.
        let circuit_inputs = circuit::proof_inputs_to_circuit(&proof_inputs)?;

        println!("Generating native ZK proof...");
        let proof = circuit_native::generate_proof_native(&circuit_inputs, &native_paths)?;
        let proof_base64 = proof.to_base64()?;

        // keys_match_circuit() above guarantees the build manifest exists.
        let build = native_paths
            .read_build_manifest()?
            .ok_or_else(|| anyhow!("missing build manifest; re-run c2pa-x509-zk-setup --force"))?;
        let assertion = X509ZkSignerProofAssertion::new(
            issuer_dn,
            ca_key_id,
            hex::encode(&manifest_data.claim_hash),
            proof_base64,
        )
        .with_artifacts(&build);

        println!("Rewriting manifest with ZK proof...");
        rewrite_manifest_with_zk_proof(&args.input, &args.output, assertion, issuing_chain)?;

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


/// The c2pa-zk-gnark prover from --keys and --gnark.
pub fn gnark_prover(keys: Option<&PathBuf>, gnark: Option<&PathBuf>) -> Result<c2pa_x509_zk_demo::third_party::Prover> {
    let keys = keys.ok_or_else(|| anyhow!("third-party mode needs --keys (a directory from c2pa-zk-gnark setup)"))?.clone();
    let cli = match gnark {
        Some(cli) => cli.clone(),
        // target/release/<this binary> -> target/c2pa-zk-gnark
        None => std::env::current_exe()?.parent().and_then(|d| d.parent()).map(|d| d.join("c2pa-zk-gnark")).ok_or_else(|| anyhow!("cannot locate c2pa-zk-gnark; pass --gnark"))?,
    };
    Ok(c2pa_x509_zk_demo::third_party::Prover { cli, keys })
}

fn third_party(args: &Args) -> Result<()> {
    use c2pa_x509_zk_demo::third_party::anonymize;
    println!("=== C2PA X.509 ZK Anonymizer (third-party mode) ===\n");
    let trust = TrustList::from_file(&args.trust_list)?;
    let prover = gnark_prover(args.keys.as_ref(), args.gnark.as_ref())?;
    println!("Proving the original signature of {:?} (this takes a few minutes)...", args.input);
    let report = anonymize(&args.input, &args.output, &trust, &prover)?;
    println!("\n✅ Anonymized asset written to {:?}", args.output);
    println!("   Issuing CA: {}", c2pa_x509_zk_demo::extract_subject_dn(&report.issuing_chain[0])?);
    println!("   Time stamp: {} (Unix)", report.time);
    println!("   Claim signature: {} bytes, replaced in place ({} spare)", report.signature_bytes, report.spare_bytes);
    println!("\nStill visible and authenticated by the claim:");
    println!("   Claim generator: {}", report.claim.claim_generator);
    println!("   Assertions: {}", report.claim.assertions.join(", "));
    if report.claim.hard_binding_exclusions.len() > 1 {
        println!(
            "\n⚠️  The hard binding excludes {} byte ranges besides the manifest store: that data (for example EXIF or XMP) is neither authenticated nor anonymized.",
            report.claim.hard_binding_exclusions.len() - 1
        );
    }
    Ok(())
}
