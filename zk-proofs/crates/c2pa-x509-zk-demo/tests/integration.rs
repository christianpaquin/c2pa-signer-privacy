use assert_cmd::Command;
use c2pa::{settings, Reader};
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use tempfile::tempdir;

fn parse_pem_chain(pem_chain: &str) -> Vec<Vec<u8>> {
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let mut certs = Vec::new();
    let mut remaining = pem_chain;

    while let Some(start) = remaining.find(start_marker) {
        let after_start = &remaining[start + start_marker.len()..];
        let end = after_start.find(end_marker).expect("malformed PEM chain");
        let base64_content: String = after_start[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD
            .decode(base64_content)
            .expect("invalid base64 in PEM chain");
        certs.push(der);
        remaining = &after_start[end + end_marker.len()..];
    }

    certs
}

fn read_cert_chain_from_asset(asset_path: &Path, disable_verify: bool) -> Vec<Vec<u8>> {
    if disable_verify {
        let settings_json = r#"{
            "verify": {
                "verify_after_reading": false
            }
        }"#;
        settings::load_settings_from_str(settings_json, "json").expect("failed to disable verification");
    }

    let reader = Reader::from_file(asset_path).expect("failed to read asset manifest");
    let manifest = reader.active_manifest().expect("missing active manifest");
    let signature = manifest.signature_info().expect("missing signature info");
    parse_pem_chain(signature.cert_chain())
}

fn run_openssl(args: &[&str], cwd: &Path) {
    let status = ProcessCommand::new("openssl")
        .args(args)
        .current_dir(cwd)
        .status()
        .expect("failed to run openssl");
    assert!(status.success(), "openssl command failed: {:?}", args);
}

fn write_leaf_extensions(path: &Path) {
    std::fs::write(
        path,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nextendedKeyUsage=critical,1.3.6.1.5.5.7.3.36\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n",
    )
    .expect("failed to write leaf extension file");
}

fn generate_alternate_cert_chain(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let ca_key = dir.join("alt-ca.key");
    let ca_cert = dir.join("alt-ca.pem");
    let signer_key = dir.join("alt-signer.key");
    let signer_csr = dir.join("alt-signer.csr");
    let signer_cert = dir.join("alt-signer.pem");
    let signer_ext = dir.join("alt-signer.ext");

    run_openssl(
        &["ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", ca_key.to_str().unwrap()],
        dir,
    );
    run_openssl(
        &[
            "req", "-x509", "-new", "-nodes",
            "-key", ca_key.to_str().unwrap(),
            "-sha256",
            "-days", "365",
            "-out", ca_cert.to_str().unwrap(),
            "-subj", "/CN=Alt ZK Test CA/O=C2PA Alt Test/C=US",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        dir,
    );

    run_openssl(
        &["ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", signer_key.to_str().unwrap()],
        dir,
    );
    run_openssl(
        &[
            "req", "-new",
            "-key", signer_key.to_str().unwrap(),
            "-out", signer_csr.to_str().unwrap(),
            "-subj", "/CN=Alt ZK Test Signer/O=C2PA Alt Test/C=US",
        ],
        dir,
    );

    write_leaf_extensions(&signer_ext);
    run_openssl(
        &[
            "x509", "-req",
            "-in", signer_csr.to_str().unwrap(),
            "-CA", ca_cert.to_str().unwrap(),
            "-CAkey", ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-out", signer_cert.to_str().unwrap(),
            "-days", "90",
            "-sha256",
            "-extfile", signer_ext.to_str().unwrap(),
        ],
        dir,
    );

    (signer_cert, signer_key, ca_cert)
}

/// Test the sign CLI creates a valid C2PA asset
#[test]
fn sign_creates_valid_asset() {
    let dir = tempdir().expect("failed to create temp dir");
    let output_path = dir.path().join("signed.png");

    Command::cargo_bin("c2pa-x509-zk-sign")
        .unwrap()
        .args([
            "--input", "fixtures/cards.png",
            "--output", output_path.to_str().unwrap(),
            "--cert", "fixtures/certs/signer-cert.pem",
            "--key", "fixtures/certs/signer-key.pem",
            "--ca", "fixtures/certs/ca-cert.pem",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed asset written"));

    assert!(output_path.exists());
}

/// Test the editor CLI creates an anonymized asset with placeholder proof
#[test]
fn editor_creates_anonymized_asset_placeholder() {
    let dir = tempdir().expect("failed to create temp dir");
    let signed_path = dir.path().join("signed.png");
    let anon_path = dir.path().join("anon.png");

    // First sign the asset
    Command::cargo_bin("c2pa-x509-zk-sign")
        .unwrap()
        .args([
            "--input", "fixtures/cards.png",
            "--output", signed_path.to_str().unwrap(),
            "--cert", "fixtures/certs/signer-cert.pem",
            "--key", "fixtures/certs/signer-key.pem",
            "--ca", "fixtures/certs/ca-cert.pem",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    // Then anonymize it (use --placeholder for testing without full ZK setup)
    Command::cargo_bin("c2pa-x509-zk-editor")
        .unwrap()
        .args([
            "--input", signed_path.to_str().unwrap(),
            "--output", anon_path.to_str().unwrap(),
            "--ca", "fixtures/certs/ca-cert.pem",
            "--placeholder",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success()
        .stdout(predicate::str::contains("Anonymized asset written"));

    assert!(anon_path.exists());
}

/// Test the verify CLI correctly identifies placeholder proofs
#[test]
fn verify_recognizes_placeholder_proof() {
    let dir = tempdir().expect("failed to create temp dir");
    let signed_path = dir.path().join("signed.png");
    let anon_path = dir.path().join("anon.png");

    // Sign
    Command::cargo_bin("c2pa-x509-zk-sign")
        .unwrap()
        .args([
            "--input", "fixtures/cards.png",
            "--output", signed_path.to_str().unwrap(),
            "--cert", "fixtures/certs/signer-cert.pem",
            "--key", "fixtures/certs/signer-key.pem",
            "--ca", "fixtures/certs/ca-cert.pem",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    // Anonymize (use --placeholder for testing)
    Command::cargo_bin("c2pa-x509-zk-editor")
        .unwrap()
        .args([
            "--input", signed_path.to_str().unwrap(),
            "--output", anon_path.to_str().unwrap(),
            "--ca", "fixtures/certs/ca-cert.pem",
            "--placeholder",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    // Verify (should recognize placeholder)
    Command::cargo_bin("c2pa-x509-zk-verify")
        .unwrap()
        .args([
            "--input", anon_path.to_str().unwrap(),
            "--ca", "fixtures/certs/ca-cert.pem",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success()
        .stdout(predicate::str::contains("Issuer key ID matches trusted CA"))
        .stderr(predicate::str::contains("placeholder"));
}

/// Test verification fails with wrong CA
#[test]
fn verify_fails_with_wrong_ca() {
    let dir = tempdir().expect("failed to create temp dir");
    let signed_path = dir.path().join("signed.png");
    let anon_path = dir.path().join("anon.png");
    
    // Create a different CA for testing
    let wrong_ca_path = dir.path().join("wrong-ca.pem");
    std::fs::write(&wrong_ca_path, r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegDjlNMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBldyb25n
Q0EwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjARMQ8wDQYDVQQDDAZXcm9u
Z0NBMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMJe7M9gR7ylPEKVq0LV5V3kFr2ViPhn
yY9hJaEqEdP+M3+KkP/nRJH9DMLE6BNzNKNb/9BQJEE7ZwA8vBqKNZ0CAwEAAaNTMFEw
HQYDVR0OBBYEFDhXTvGcbQo/vDC/N6oNhHNHZIuQMB8GA1UdIwQYMBaAFDhXTvGcbQo/
vDC/N6oNhHNHZIuQMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADQQBXkN3S
-----END CERTIFICATE-----"#).unwrap();

    // Sign with real CA
    Command::cargo_bin("c2pa-x509-zk-sign")
        .unwrap()
        .args([
            "--input", "fixtures/cards.png",
            "--output", signed_path.to_str().unwrap(),
            "--cert", "fixtures/certs/signer-cert.pem",
            "--key", "fixtures/certs/signer-key.pem",
            "--ca", "fixtures/certs/ca-cert.pem",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    // Anonymize with real CA (use --placeholder for testing)
    Command::cargo_bin("c2pa-x509-zk-editor")
        .unwrap()
        .args([
            "--input", signed_path.to_str().unwrap(),
            "--output", anon_path.to_str().unwrap(),
            "--ca", "fixtures/certs/ca-cert.pem",
            "--placeholder",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    // Verify with wrong CA should fail
    Command::cargo_bin("c2pa-x509-zk-verify")
        .unwrap()
        .args([
            "--input", anon_path.to_str().unwrap(),
            "--ca", wrong_ca_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key ID mismatch"));
}

/// Test verification fails if the anonymized asset bytes are modified.
#[test]
fn verify_fails_for_tampered_asset() {
    let dir = tempdir().expect("failed to create temp dir");
    let signed_path = dir.path().join("signed.png");
    let anon_path = dir.path().join("anon.png");
    let tampered_path = dir.path().join("tampered.png");

    Command::cargo_bin("c2pa-x509-zk-sign")
        .unwrap()
        .args([
            "--input", "fixtures/cards.png",
            "--output", signed_path.to_str().unwrap(),
            "--cert", "fixtures/certs/signer-cert.pem",
            "--key", "fixtures/certs/signer-key.pem",
            "--ca", "fixtures/certs/ca-cert.pem",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    Command::cargo_bin("c2pa-x509-zk-editor")
        .unwrap()
        .args([
            "--input", signed_path.to_str().unwrap(),
            "--output", anon_path.to_str().unwrap(),
            "--ca", "fixtures/certs/ca-cert.pem",
            "--placeholder",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    let mut bytes = std::fs::read(&anon_path).expect("failed to read anonymized asset");
    let idx = bytes.iter().rposition(|byte| *byte != 0).expect("asset should contain non-zero bytes");
    bytes[idx] ^= 0x01;
    std::fs::write(&tampered_path, bytes).expect("failed to write tampered asset");

    Command::cargo_bin("c2pa-x509-zk-verify")
        .unwrap()
        .args([
            "--input", tampered_path.to_str().unwrap(),
            "--ca", "fixtures/certs/ca-cert.pem",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Asset binding digest mismatch"));
}

#[test]
fn anonymized_manifest_preserves_original_cert_chain() {
    let dir = tempdir().expect("failed to create temp dir");
    let signed_path = dir.path().join("signed-alt.png");
    let anon_path = dir.path().join("anon-alt.png");
    let (signer_cert, signer_key, ca_cert) = generate_alternate_cert_chain(dir.path());

    Command::cargo_bin("c2pa-x509-zk-sign")
        .unwrap()
        .args([
            "--input", "fixtures/cards.png",
            "--output", signed_path.to_str().unwrap(),
            "--cert", signer_cert.to_str().unwrap(),
            "--key", signer_key.to_str().unwrap(),
            "--ca", ca_cert.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    Command::cargo_bin("c2pa-x509-zk-editor")
        .unwrap()
        .args([
            "--input", signed_path.to_str().unwrap(),
            "--output", anon_path.to_str().unwrap(),
            "--ca", ca_cert.to_str().unwrap(),
            "--placeholder",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    let signed_chain = read_cert_chain_from_asset(&signed_path, false);
    let anonymized_bytes = std::fs::read(&anon_path).expect("failed to read anonymized asset");
    let signer_cert_der = signed_chain[0].clone();
    let ca_cert_der = signed_chain[1].clone();

    assert!(
        anonymized_bytes.windows(signer_cert_der.len()).any(|window| window == signer_cert_der.as_slice()),
        "anonymized asset does not contain the alternate signer certificate"
    );
    assert!(
        anonymized_bytes.windows(ca_cert_der.len()).any(|window| window == ca_cert_der.as_slice()),
        "anonymized asset does not contain the alternate CA certificate"
    );
}

/// Full end-to-end test with real ZK proof generation and verification.
/// This test is slower (~1 minute) because it generates actual Groth16 proofs.
/// It's marked #[ignore] by default - run with `cargo test -- --ignored` to include.
#[test]
#[ignore]
fn full_e2e_with_real_zk_proof() {
    let dir = tempdir().expect("failed to create temp dir");
    let signed_path = dir.path().join("signed.png");
    let anon_path = dir.path().join("anon.png");

    // Step 1: Sign the asset with standard X.509/ECDSA
    Command::cargo_bin("c2pa-x509-zk-sign")
        .unwrap()
        .args([
            "--input", "fixtures/cards.png",
            "--output", signed_path.to_str().unwrap(),
            "--cert", "fixtures/certs/signer-cert.pem",
            "--key", "fixtures/certs/signer-key.pem",
            "--ca", "fixtures/certs/ca-cert.pem",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed asset written"));

    // Step 2: Anonymize with real ZK proof (no --placeholder flag)
    // Note: This step takes ~2-3 minutes due to ZK proof generation
    Command::cargo_bin("c2pa-x509-zk-editor")
        .unwrap()
        .args([
            "--input", signed_path.to_str().unwrap(),
            "--output", anon_path.to_str().unwrap(),
            "--ca", "fixtures/certs/ca-cert.pem",
            "--signer-key", "fixtures/certs/signer-key.pem",
            "--circuits-dir", "circuits",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .timeout(std::time::Duration::from_secs(300))
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof generated"))
        .stdout(predicate::str::contains("Anonymized asset written"));

    assert!(anon_path.exists());

    // Step 3: Verify the ZK proof
    Command::cargo_bin("c2pa-x509-zk-verify")
        .unwrap()
        .args([
            "--input", anon_path.to_str().unwrap(),
            "--ca", "fixtures/certs/ca-cert.pem",
            "--circuits-dir", "circuits",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success()
        .stdout(predicate::str::contains("ZK proof verified successfully"));
}
