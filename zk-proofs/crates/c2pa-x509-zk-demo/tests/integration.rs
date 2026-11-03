//! CLI integration tests. Each test generates its own C2PA-like test PKI
//! (root -> issuing CA -> signer) with generate-test-pki.sh.

use assert_cmd::assert::Assert;
use assert_cmd::Command;
use c2pa_x509_zk_demo::{
    compute_manifest_stripped_asset_digest, extract_subject_dn,
    manifest::{read_anonymized_asset, rewrite_manifest_with_zk_proof},
    pem_to_der_certs, spki_key_id, X509ZkSignerProofAssertion,
};
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::{tempdir, TempDir};

/// The zk-proofs/ directory.
fn zk_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn cards() -> PathBuf {
    zk_root().join("fixtures/cards.png")
}

/// A generated test PKI in a temporary directory.
struct Pki {
    _dir: TempDir,
    path: PathBuf,
}

impl Pki {
    fn generate(name: &str) -> Self {
        let dir = tempdir().unwrap();
        let ok = std::process::Command::new("bash")
            .arg(zk_root().join("generate-test-pki.sh"))
            .arg(dir.path())
            .arg(name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "generate-test-pki.sh failed");
        let path = dir.path().to_path_buf();
        Self { _dir: dir, path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.file(name)).unwrap()
    }
}

fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Sign `cards.png` with the PKI's signer; the chain is signer + issuing CA.
fn sign(pki: &Pki, output: &Path) {
    Command::cargo_bin("c2pa-x509-zk-sign")
        .unwrap()
        .args([
            "--input", path_str(&cards()),
            "--output", path_str(output),
            "--cert", path_str(&pki.file("signer.pem")),
            "--key", path_str(&pki.file("signer.key")),
            "--ca", path_str(&pki.file("issuing-ca.pem")),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed asset written"));
}

fn anonymize_placeholder(signed: &Path, output: &Path, trust_list: &Path) -> Assert {
    Command::cargo_bin("c2pa-x509-zk-anonymizer")
        .unwrap()
        .args([
            "--input", path_str(signed),
            "--output", path_str(output),
            "--trust-list", path_str(trust_list),
            "--placeholder",
        ])
        .current_dir(zk_root())
        .assert()
}

fn verify(anonymized: &Path, trust_list: &Path) -> Assert {
    Command::cargo_bin("c2pa-x509-zk-verify")
        .unwrap()
        .args(["--input", path_str(anonymized), "--trust-list", path_str(trust_list)])
        .current_dir(zk_root())
        .assert()
}

/// Sign and anonymize (placeholder proof) with the PKI's own trust list.
fn signed_and_anonymized(pki: &Pki, dir: &Path) -> (PathBuf, PathBuf) {
    let signed = dir.join("signed.png");
    let anon = dir.join("anon.png");
    sign(pki, &signed);
    anonymize_placeholder(&signed, &anon, &pki.file("trust-list.pem")).success();
    (signed, anon)
}

/// The signed asset's x5chain, read without c2pa-rs trust validation.
fn signed_chain(asset: &Path) -> Vec<Vec<u8>> {
    c2pa::settings::Settings::from_string(r#"{"verify": {"verify_after_reading": false}}"#, "json").unwrap();
    let reader = c2pa::Reader::from_file(asset).unwrap();
    let info = reader.active_manifest().unwrap().signature_info().unwrap().cert_chain().to_string();
    pem_to_der_certs(&info).unwrap()
}

/// Build an anonymized asset directly through the library, with a chosen
/// x5chain and assertion, to exercise verifier checks the CLI never violates.
fn crafted_asset(dir: &Path, issuing_chain: Vec<Vec<u8>>, issuer: String, key_id: String) -> PathBuf {
    let out = dir.join("crafted.png");
    let assertion = X509ZkSignerProofAssertion::new(
        issuer,
        key_id,
        hex::encode(compute_manifest_stripped_asset_digest(&cards()).unwrap()),
        "PLACEHOLDER_PROOF".into(),
    );
    rewrite_manifest_with_zk_proof(&cards(), &out, assertion, issuing_chain).unwrap();
    out
}

#[test]
fn sign_embeds_signer_and_issuing_ca() {
    let pki = Pki::generate("Sign Test");
    let dir = tempdir().unwrap();
    let signed = dir.path().join("signed.png");
    sign(&pki, &signed);
    assert_eq!(signed_chain(&signed), vec![pki.read("signer.der"), pki.read("issuing-ca.der")]);
}

#[test]
fn anonymized_x5chain_holds_only_the_issuing_ca() {
    let pki = Pki::generate("Anon Test");
    let dir = tempdir().unwrap();
    let (_, anon) = signed_and_anonymized(&pki, dir.path());

    let (assertion, chain) = read_anonymized_asset(&anon).unwrap();
    assert_eq!(chain, vec![pki.read("issuing-ca.der")]);
    assert_eq!(assertion.issuer, extract_subject_dn(&pki.read("issuing-ca.der")).unwrap());
    assert_eq!(assertion.issuer_key_id, spki_key_id(&pki.read("issuing-ca.der")).unwrap());
}

/// The verifier gets through every trust check and stops at the placeholder
/// proof (exit code 2), for each trust list form.
#[test]
fn verify_accepts_chain_to_trust_list_then_stops_at_placeholder() {
    let pki = Pki::generate("Verify Test");
    let dir = tempdir().unwrap();
    let (_, anon) = signed_and_anonymized(&pki, dir.path());

    // PEM bundle, the JSON trust list format, and a root-only trust list
    // (the issuing CA is then validated by chaining to the root).
    for trust_list in ["trust-list.pem", "trust-list.json", "root.pem"] {
        verify(&anon, &pki.file(trust_list))
            .code(2)
            .stdout(predicate::str::contains("Issuing chain validates against the trust list"))
            .stdout(predicate::str::contains("Assertion issuer matches the issuing CA"))
            .stderr(predicate::str::contains("placeholder"));
    }
}

#[test]
fn verify_rejects_chain_not_in_trust_list() {
    let pki = Pki::generate("Verify Test");
    let other = Pki::generate("Other PKI");
    let dir = tempdir().unwrap();
    let (_, anon) = signed_and_anonymized(&pki, dir.path());

    verify(&anon, &other.file("trust-list.pem"))
        .failure()
        .stderr(predicate::str::contains("Issuing chain is not trusted"));
}

#[test]
fn anonymizer_rejects_signer_not_in_trust_list() {
    let pki = Pki::generate("Anon Test");
    let other = Pki::generate("Other PKI");
    let dir = tempdir().unwrap();
    let signed = dir.path().join("signed.png");
    sign(&pki, &signed);

    anonymize_placeholder(&signed, &dir.path().join("anon.png"), &other.file("trust-list.pem"))
        .failure()
        .stderr(predicate::str::contains("does not chain to the trust list"));
}

#[test]
fn verify_rejects_assertion_not_matching_x5chain() {
    let pki = Pki::generate("Verify Test");
    let dir = tempdir().unwrap();
    // x5chain holds the issuing CA, but the assertion names the root.
    let anon = crafted_asset(
        dir.path(),
        vec![pki.read("issuing-ca.der")],
        extract_subject_dn(&pki.read("root.der")).unwrap(),
        spki_key_id(&pki.read("root.der")).unwrap(),
    );
    verify(&anon, &pki.file("trust-list.pem"))
        .failure()
        .stderr(predicate::str::contains("does not match the issuing CA"));
}

#[test]
fn verify_rejects_signer_certificate_in_x5chain() {
    let pki = Pki::generate("Verify Test");
    let dir = tempdir().unwrap();
    // A standard C2PA x5chain (signer first): not an issuing chain.
    let anon = crafted_asset(
        dir.path(),
        vec![pki.read("signer.der"), pki.read("issuing-ca.der")],
        extract_subject_dn(&pki.read("issuing-ca.der")).unwrap(),
        spki_key_id(&pki.read("issuing-ca.der")).unwrap(),
    );
    verify(&anon, &pki.file("trust-list.pem"))
        .failure()
        .stderr(predicate::str::contains("not a CA certificate"));
}

/// A C2PA signer with an arbitrary x5chain, to produce signed assets the
/// signing CLI refuses to create (for example, a malformed chain order).
struct ChainSigner {
    key: p256::ecdsa::SigningKey,
    chain: Vec<Vec<u8>>,
}

impl c2pa::Signer for ChainSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, Signature};
        let sig: Signature = self.key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }
    fn alg(&self) -> c2pa::SigningAlg {
        c2pa::SigningAlg::Es256
    }
    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(self.chain.clone())
    }
    fn reserve_size(&self) -> usize {
        20_000
    }
}

fn signer_key(pki: &Pki) -> p256::ecdsa::SigningKey {
    let der = pki.file("signer-key.der");
    let ok = std::process::Command::new("openssl")
        .args(["ec", "-in", path_str(&pki.file("signer.key")), "-outform", "DER", "-out", path_str(&der)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "openssl ec failed");
    p256::SecretKey::from_sec1_der(&std::fs::read(der).unwrap()).unwrap().into()
}

/// Regression test (PR #14 review): a signed x5chain with certificates after
/// the trusted issuing CA, here a duplicate of the signer certificate. The
/// anonymizer must embed only the validated path, never the signer.
#[test]
fn anonymizer_drops_certificates_after_the_anchor() {
    let pki = Pki::generate("Surplus Test");
    let dir = tempdir().unwrap();
    let signed = dir.path().join("signed.png");
    let anon = dir.path().join("anon.png");

    let signer = ChainSigner {
        key: signer_key(&pki),
        chain: vec![pki.read("signer.der"), pki.read("issuing-ca.der"), pki.read("signer.der")],
    };
    let mut builder = c2pa::Builder::from_json(r#"{"claim_generator_info": [{"name": "surplus-test"}]}"#).unwrap();
    builder.sign_file(&signer, &cards(), &signed).unwrap();
    assert_eq!(signed_chain(&signed).len(), 3);

    anonymize_placeholder(&signed, &anon, &pki.file("trust-list.pem")).success();

    let (_, chain) = read_anonymized_asset(&anon).unwrap();
    assert_eq!(chain, vec![pki.read("issuing-ca.der")]);
    assert!(
        !contains(&std::fs::read(&anon).unwrap(), &pki.read("signer.der")),
        "anonymized asset contains the signer certificate"
    );
}

#[test]
fn verify_rejects_x5chain_with_certificates_after_the_anchor() {
    let pki = Pki::generate("Verify Test");
    let dir = tempdir().unwrap();
    // The issuing CA is an anchor; the root after it is surplus.
    let anon = crafted_asset(
        dir.path(),
        vec![pki.read("issuing-ca.der"), pki.read("root.der")],
        extract_subject_dn(&pki.read("issuing-ca.der")).unwrap(),
        spki_key_id(&pki.read("issuing-ca.der")).unwrap(),
    );
    verify(&anon, &pki.file("trust-list.pem"))
        .failure()
        .stderr(predicate::str::contains("after the trust anchor"));
}

/// Regression test (PR #14 review): renewing the signer certificate must not
/// replace the trust anchors, so assets anonymized before the renewal still
/// validate, and must keep the signer key.
#[test]
fn signer_renewal_keeps_trust_anchors_and_key() {
    let pki = Pki::generate("Renewal Test");
    let dir = tempdir().unwrap();
    let (_, anon) = signed_and_anonymized(&pki, dir.path());
    let (anchors, key, cert) = (pki.read("trust-list.pem"), pki.read("signer.key"), pki.read("signer.der"));

    let ok = std::process::Command::new("bash")
        .arg(zk_root().join("generate-test-pki.sh"))
        .args(["--renew-signer", path_str(&pki.path)])
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "generate-test-pki.sh --renew-signer failed");

    assert_eq!(pki.read("trust-list.pem"), anchors, "renewal replaced the trust anchors");
    assert_eq!(pki.read("signer.key"), key, "renewal replaced the signer key");
    assert_ne!(pki.read("signer.der"), cert, "renewal did not issue a new signer certificate");
    verify(&anon, &pki.file("trust-list.pem"))
        .code(2)
        .stdout(predicate::str::contains("Issuing chain validates against the trust list"));
}

/// Verification fails if the anonymized asset bytes are modified.
#[test]
fn verify_fails_for_tampered_asset() {
    let pki = Pki::generate("Tamper Test");
    let dir = tempdir().unwrap();
    let (_, anon) = signed_and_anonymized(&pki, dir.path());

    let mut bytes = std::fs::read(&anon).unwrap();
    let idx = bytes.iter().rposition(|byte| *byte != 0).unwrap();
    bytes[idx] ^= 0x01;
    let tampered = dir.path().join("tampered.png");
    std::fs::write(&tampered, bytes).unwrap();

    verify(&tampered, &pki.file("trust-list.pem"))
        .failure()
        .stderr(predicate::str::contains("Asset binding digest mismatch"));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Regression test for issue #6: the anonymized asset must not carry anything
/// that identifies the signer. Scans the raw file bytes rather than relying on
/// a C2PA parser, which can fail to decode the custom COSE structure and so
/// report an empty certificate chain even when one is present.
#[test]
fn anonymized_asset_does_not_reveal_signer() {
    use der::{Decode, Encode};
    use x509_cert::Certificate;

    let pki = Pki::generate("Leak Test");
    let dir = tempdir().unwrap();
    let (signed, anon) = signed_and_anonymized(&pki, dir.path());

    let signed_label = c2pa::Reader::from_file(&signed)
        .unwrap()
        .active_label()
        .expect("signed asset has no active manifest")
        .to_string();
    let anonymized_bytes = std::fs::read(&anon).unwrap();

    let signer_cert_der = pki.read("signer.der");
    let signer = Certificate::from_der(&signer_cert_der).unwrap();
    let tbs = &signer.tbs_certificate;
    let signer_pubkey = tbs.subject_public_key_info.subject_public_key.raw_bytes();
    let signer_serial = tbs.serial_number.as_bytes();
    let signer_subject = tbs.subject.to_der().unwrap();

    assert!(!contains(&anonymized_bytes, &signer_cert_der), "anonymized asset contains the signer certificate");
    assert!(!contains(&anonymized_bytes, signer_pubkey), "anonymized asset contains the signer public key");
    assert!(!contains(&anonymized_bytes, signer_serial), "anonymized asset contains the signer certificate serial number");
    assert!(!contains(&anonymized_bytes, &signer_subject), "anonymized asset contains the signer subject DN");
    assert!(
        !contains(&anonymized_bytes, signed_label.as_bytes()),
        "anonymized asset still contains the original signed manifest"
    );
}

/// Full end-to-end test with real ZK proof generation and verification.
/// This test is slow (~10 minutes, ~12 GB of RAM) because it generates an actual Groth16 proof.
/// It's marked #[ignore] by default - run with `cargo test -- --ignored` to include.
#[test]
#[ignore]
fn full_e2e_with_real_zk_proof() {
    let pki = Pki::generate("E2E Test");
    let dir = tempdir().unwrap();
    let signed = dir.path().join("signed.png");
    let anon = dir.path().join("anon.png");
    sign(&pki, &signed);

    // Note: This step takes ~10 minutes due to ZK proof generation
    Command::cargo_bin("c2pa-x509-zk-anonymizer")
        .unwrap()
        .args([
            "--input", path_str(&signed),
            "--output", path_str(&anon),
            "--trust-list", path_str(&pki.file("trust-list.json")),
            "--signer-key", path_str(&pki.file("signer.key")),
            "--circuits-dir", "circuits",
        ])
        .current_dir(zk_root())
        .timeout(std::time::Duration::from_secs(45 * 60))
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof generated"))
        .stdout(predicate::str::contains("Anonymized asset written"));

    verify(&anon, &pki.file("trust-list.pem"))
        .success()
        .stdout(predicate::str::contains("ZK proof verified successfully"));
}

/// Regression test for the certificate field-binding forgery: a prover with no
/// certificate takes a genuine certificate issued by the trusted CA, appends
/// their own public key and forged validity dates after it (outside the
/// TBSCertificate the CA signed), and points the circuit's offsets there.
/// The result must not be a proof that verifies.
///
/// Witness generation runs with ark-circom's default `sanity_check: false`, so
/// unsatisfied constraints do not stop proof generation; the resulting proof
/// must instead fail verification.
///
/// Slow (~7-10 minutes, ~12 GB of RAM) and needs the built circuit and keys, so
/// it is ignored by default:
///   cargo test --release -- --ignored forged_key_outside_signed_tbs_is_rejected
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn forged_key_outside_signed_tbs_is_rejected() {
    use c2pa_x509_zk_demo::{circuit, ManifestData, NativeCircuitPaths};
    use p256::ecdsa::SigningKey;

    let pki = Pki::generate("Forgery Test");
    let victim_cert_der = pki.read("signer.der");
    let ca_cert_der = pki.read("issuing-ca.der");

    // Attacker key: never certified by anyone.
    let attacker = SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap();
    let point = attacker.verifying_key().to_encoded_point(false);

    let manifest_data = ManifestData {
        claim_hash: compute_manifest_stripped_asset_digest(&cards()).unwrap(),
        leaf_cert_der: victim_cert_der.clone(),
        ca_certs_der: vec![ca_cert_der.clone()],
        cose_signature: Vec::new(),
        photo_timestamp: 1_893_456_000, // 2030-01-01, after the victim cert expires
    };
    let proof_inputs =
        circuit::prepare_inputs(&manifest_data, &attacker.to_bytes(), &ca_cert_der).unwrap();
    let mut inputs = circuit::proof_inputs_to_circuit(&proof_inputs).unwrap();

    // Append 0x04 || X || Y and two UTCTime fields after the certificate.
    let mut appended = point.as_bytes().to_vec();
    let not_before_offset = victim_cert_der.len() + appended.len();
    appended.extend_from_slice(&[0x17, 0x0d]);
    appended.extend_from_slice(b"200101000000Z");
    let not_after_offset = victim_cert_der.len() + appended.len();
    appended.extend_from_slice(&[0x17, 0x0d]);
    appended.extend_from_slice(b"491231235959Z");
    for (i, b) in appended.iter().enumerate() {
        inputs.cert_der[victim_cert_der.len() + i] = b.to_string();
    }
    inputs.spki_x_offset = (victim_cert_der.len() + 1).to_string();
    inputs.not_before_offset = not_before_offset.to_string();
    inputs.not_after_offset = not_after_offset.to_string();

    let paths = NativeCircuitPaths::default_for_circuit(&zk_root().join("circuits"), "x509_issue_and_possession");
    assert!(paths.setup_complete(), "circuit setup required: see README Building Circuits");

    // Either proof generation fails, or the proof it produces does not verify.
    let accepted = match c2pa_x509_zk_demo::generate_proof_native(&inputs, &paths) {
        Err(_) => false,
        Ok(proof) => c2pa_x509_zk_demo::verify_proof_native(&proof, &paths).unwrap_or(false),
    };
    assert!(
        !accepted,
        "circuit accepted a public key from outside the CA-signed TBSCertificate"
    );
}
