use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

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
