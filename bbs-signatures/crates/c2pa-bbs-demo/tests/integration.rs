use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn issue_bin() -> &'static str {
    env!("CARGO_BIN_EXE_c2pa-bbs-issue")
}

fn sign_bin() -> &'static str {
    env!("CARGO_BIN_EXE_c2pa-bbs-sign")
}

fn verify_bin() -> &'static str {
    env!("CARGO_BIN_EXE_c2pa-bbs-verify")
}

fn issue_credential(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let credential_path = dir.path().join("credential.json");

    Command::new(issue_bin())
        .args([
            "--output",
            credential_path.to_str().unwrap(),
            "--issuer",
            "TestIssuer",
            "--policy",
            "test-policy",
            "--editor-id",
            "editor-1234",
            "--device-id",
            "device-9876",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    credential_path
}

/// Round-trip test: sign an asset and verify it successfully.
#[test]
fn sign_then_verify_succeeds() {
    let dir = tempdir().expect("failed to create temp dir");
    let output_path = dir.path().join("signed.png");
    let credential_path = issue_credential(&dir);

    // Sign
    Command::new(sign_bin())
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
            "--credential",
            credential_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    // Verify
    Command::new(verify_bin())
        .args(["--input", output_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("BBS signer proof verified successfully"));
}

/// Verification with explicit issuer/policy that match should succeed.
#[test]
fn verify_with_matching_attributes_succeeds() {
    let dir = tempdir().expect("failed to create temp dir");
    let output_path = dir.path().join("signed.png");
    let credential_path = issue_credential(&dir);

    Command::new(sign_bin())
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
            "--credential",
            credential_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    Command::new(verify_bin())
        .args([
            "--input",
            output_path.to_str().unwrap(),
            "--issuer",
            "TestIssuer",
            "--policy",
            "test-policy",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("issuer: TestIssuer"))
        .stdout(predicates::str::contains("policy: test-policy"));
}

/// Verification with mismatched issuer should fail.
#[test]
fn verify_with_wrong_issuer_fails() {
    let dir = tempdir().expect("failed to create temp dir");
    let output_path = dir.path().join("signed.png");
    let credential_path = issue_credential(&dir);

    Command::new(sign_bin())
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
            "--credential",
            credential_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    Command::new(verify_bin())
        .args([
            "--input",
            output_path.to_str().unwrap(),
            "--issuer",
            "WrongIssuer",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("issuer mismatch"));
}

/// Verification with mismatched policy should fail.
#[test]
fn verify_with_wrong_policy_fails() {
    let dir = tempdir().expect("failed to create temp dir");
    let output_path = dir.path().join("signed.png");
    let credential_path = issue_credential(&dir);

    Command::new(sign_bin())
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
            "--credential",
            credential_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    Command::new(verify_bin())
        .args([
            "--input",
            output_path.to_str().unwrap(),
            "--policy",
            "wrong-policy",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("policy mismatch"));
}

/// Tampering with the signed asset should invalidate verification.
#[test]
fn tampered_asset_fails_verification() {
    let dir = tempdir().expect("failed to create temp dir");
    let output_path = dir.path().join("signed.png");
    let credential_path = issue_credential(&dir);

    Command::new(sign_bin())
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
            "--credential",
            credential_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    let mut bytes = fs::read(&output_path).expect("failed to read signed asset");
    bytes.push(b'X');
    fs::write(&output_path, bytes).expect("failed to tamper with signed asset");

    Command::new(verify_bin())
        .args(["--input", output_path.to_str().unwrap()])
        .assert()
        .failure();
}
