use assert_cmd::Command;
use tempfile::tempdir;

/// Round-trip test: sign an asset and verify it successfully.
#[test]
fn sign_then_verify_succeeds() {
    let dir = tempdir().expect("failed to create temp dir");
    let output_path = dir.path().join("signed.png");

    // Sign
    Command::cargo_bin("c2pa-bbs-sign")
        .unwrap()
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    // Verify
    Command::cargo_bin("c2pa-bbs-verify")
        .unwrap()
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

    Command::cargo_bin("c2pa-bbs-sign")
        .unwrap()
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
            "--issuer",
            "TestIssuer",
            "--policy",
            "test-policy",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    Command::cargo_bin("c2pa-bbs-verify")
        .unwrap()
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

    Command::cargo_bin("c2pa-bbs-sign")
        .unwrap()
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
            "--issuer",
            "RealIssuer",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    Command::cargo_bin("c2pa-bbs-verify")
        .unwrap()
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

    Command::cargo_bin("c2pa-bbs-sign")
        .unwrap()
        .args([
            "--input",
            "fixtures/cards.png",
            "--output",
            output_path.to_str().unwrap(),
            "--policy",
            "correct-policy",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_owned() + "/../..")
        .assert()
        .success();

    Command::cargo_bin("c2pa-bbs-verify")
        .unwrap()
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
