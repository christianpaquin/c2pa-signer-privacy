//! Fixtures for third-party anonymization (roadmap E2b): a test PKI that
//! mirrors a real device deployment (`generate-test-pki.sh --mirror`) and an
//! asset signed under it with a local test TSA. These tests check that the
//! fixture is a standard, trusted C2PA asset with the same structure as real
//! ones, and pin the exact bytes the E2b circuit must hash.

use assert_cmd::Command;
use c2pa_x509_zk_demo::jumbf::{active_manifest, manifest_store};
use c2pa_x509_zk_demo::original_signature::{
    imprint_matches_sha256, tst_info, OriginalSignature, TimeStampVersion, COSE_ALG_ES256,
};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::{tempdir, TempDir};
use x509_cert::der::Decode;

const C2PA_CLAIM_SIGNING_EKU: &str = "1.3.6.1.4.1.62558.2.1";
const EMAIL_PROTECTION_EKU: &str = "1.3.6.1.5.5.7.3.4";
const TIME_STAMPING_EKU: &str = "1.3.6.1.5.5.7.3.8";

fn zk_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A mirror-profile PKI and an asset signed under it.
struct Fixture {
    dir: TempDir,
}

impl Fixture {
    /// `time_stamp`: sign with the local TSA.
    fn new(mirror: bool, time_stamp: bool) -> Self {
        Self::with_claim_version(mirror, time_stamp, 2)
    }

    fn with_claim_version(mirror: bool, time_stamp: bool, claim_version: u8) -> Self {
        let dir = tempdir().unwrap();
        let mut generate = std::process::Command::new("bash");
        generate.arg(zk_root().join("generate-test-pki.sh"));
        if mirror {
            generate.arg("--mirror");
        }
        let ok = generate.arg(dir.path().join("pki")).arg("Fixture").stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success();
        assert!(ok, "generate-test-pki.sh failed");

        let fixture = Self { dir };
        let mut sign = Command::cargo_bin("c2pa-x509-zk-sign").unwrap();
        sign.arg("--input").arg(zk_root().join("fixtures/cards.png")).arg("--output").arg(fixture.signed());
        for (flag, file) in [("--cert", "signer.pem"), ("--key", "signer.key"), ("--ca", "issuing-ca.pem")] {
            sign.arg(flag).arg(fixture.pki(file));
        }
        sign.arg("--claim-version").arg(claim_version.to_string());
        if time_stamp {
            sign.arg("--tsa-cert").arg(fixture.pki("tsa.pem")).arg("--tsa-key").arg(fixture.pki("tsa.key"));
        }
        sign.assert().success();
        fixture
    }

    fn pki(&self, name: &str) -> PathBuf {
        self.dir.path().join("pki").join(name)
    }

    fn signed(&self) -> PathBuf {
        self.dir.path().join("signed.png")
    }

    fn original(&self) -> OriginalSignature {
        OriginalSignature::from_asset(&self.signed()).unwrap()
    }
}

/// The named curve of a certificate's EC public key.
fn key_curve(cert: &x509_cert::Certificate) -> const_oid::ObjectIdentifier {
    let params = cert.tbs_certificate.subject_public_key_info.algorithm.parameters.as_ref().unwrap();
    params.decode_as().unwrap()
}

/// Validate with c2pa against some of the fixture's trust lists.
fn c2pa_reader(asset: &Path, fixture: &Fixture, trust_lists: &[&str]) -> c2pa::Reader {
    let anchors = trust_lists
        .iter()
        .map(|f| std::fs::read_to_string(fixture.pki(f)).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let ekus = [C2PA_CLAIM_SIGNING_EKU, EMAIL_PROTECTION_EKU, TIME_STAMPING_EKU].join("\n");
    let settings = serde_json::json!({
        "trust": { "trust_anchors": anchors, "trust_config": ekus },
        "verify": { "verify_trust": true, "verify_timestamp_trust": true },
    });
    let context = c2pa::Context::new().with_settings(settings).unwrap();
    c2pa::Reader::from_context(context).with_stream("image/png", std::fs::File::open(asset).unwrap()).unwrap()
}

#[test]
fn mirror_fixture_is_a_trusted_time_stamped_c2pa_asset() {
    let fixture = Fixture::new(true, true);
    let reader = c2pa_reader(&fixture.signed(), &fixture, &["trust-list.pem", "tsa-trust-list.pem"]);
    let (success, failure) = codes(&reader);
    assert!(failure.is_empty(), "failures: {failure:?}");
    for code in ["timeStamp.trusted", "signingCredential.trusted", "claimSignature.validated", "assertion.dataHash.match"] {
        assert!(success.contains(&code.to_string()), "missing {code} in {success:?}");
    }
    assert_eq!(reader.validation_state(), c2pa::ValidationState::Trusted);

    // Without the TSA's trust anchor, the time stamp is no longer trusted.
    let (success, _) = codes(&c2pa_reader(&fixture.signed(), &fixture, &["trust-list.pem"]));
    assert!(!success.contains(&"timeStamp.trusted".to_string()), "{success:?}");
}

/// The active manifest's success and failure codes.
fn codes(reader: &c2pa::Reader) -> (Vec<String>, Vec<String>) {
    let active = reader.validation_results().and_then(|r| r.active_manifest()).expect("active manifest results");
    let codes = |statuses: &[c2pa::validation_status::ValidationStatus]| statuses.iter().map(|s| s.code().to_string()).collect();
    (codes(active.success()), codes(active.failure()))
}

#[test]
fn mirror_fixture_has_the_structure_of_real_device_assets() {
    let fixture = Fixture::new(true, true);
    let original = fixture.original();
    assert_eq!(original.manifest.claim_label, "c2pa.claim.v2");
    assert_eq!(original.alg, COSE_ALG_ES256);
    // x5chain: the signer certificate, then the issuing CA (no root).
    assert_eq!(original.x5chain, vec![std::fs::read(fixture.pki("signer.der")).unwrap(), std::fs::read(fixture.pki("issuing-ca.der")).unwrap()]);
    assert_eq!(original.time_stamp.as_ref().map(|t| t.version), Some(TimeStampVersion::V2));

    // The issuing CA is P-384 and signed the signer certificate with ECDSA-SHA384.
    let signer = x509_cert::Certificate::from_der(original.signer_certificate().unwrap()).unwrap();
    assert_eq!(signer.signature_algorithm.oid, const_oid::db::rfc5912::ECDSA_WITH_SHA_384);
    let ca = x509_cert::Certificate::from_der(&original.x5chain[1]).unwrap();
    let ca_curve = key_curve(&ca);
    assert_eq!(ca_curve, const_oid::db::rfc5912::SECP_384_R_1);

    // The located signature box is the store's bytes at that range.
    let store = manifest_store(&fixture.signed()).unwrap();
    let manifest = active_manifest(&store).unwrap();
    assert_eq!(&store[manifest.cose_sign1_range.clone()], manifest.cose_sign1.as_slice());
}

#[test]
fn claim_signature_verifies_over_the_reconstructed_sig_structure() {
    let original = Fixture::new(true, true).original();
    original.verify_es256().unwrap();

    // Any change to the claim, the protected header, or the signature breaks it.
    let mut claim = original.clone();
    claim.manifest.claim[0] ^= 1;
    assert!(claim.verify_es256().is_err());
    let mut protected = original.clone();
    let last = protected.protected.len() - 1;
    protected.protected[last] ^= 1;
    assert!(protected.verify_es256().is_err());
    let mut signature = original;
    signature.signature[0] ^= 1;
    assert!(signature.verify_es256().is_err());
}

#[test]
fn time_stamp_imprint_covers_the_countersignature_structure() {
    let fixture = Fixture::new(true, true);
    let original = fixture.original();
    let info = tst_info(&original.time_stamp.as_ref().unwrap().token).unwrap();
    assert!(imprint_matches_sha256(&info, &original.countersignature_structure(TimeStampVersion::V2)));
    assert!(!imprint_matches_sha256(&info, &original.countersignature_structure(TimeStampVersion::V1)));
    assert!(!imprint_matches_sha256(&info, &original.sig_structure()));

    // The attested time lies within the signer certificate's validity.
    let signer = x509_cert::Certificate::from_der(original.signer_certificate().unwrap()).unwrap();
    let validity = signer.tbs_certificate.validity;
    let g = info.gen_time.as_bytes();
    let num = |r: std::ops::Range<usize>| std::str::from_utf8(&g[r]).unwrap().parse::<u16>().unwrap();
    let gen_time = x509_cert::der::DateTime::new(num(0..4), num(4..6) as u8, num(6..8) as u8, num(8..10) as u8, num(10..12) as u8, num(12..14) as u8)
        .unwrap()
        .unix_duration();
    assert!(validity.not_before.to_unix_duration() <= gen_time && gen_time <= validity.not_after.to_unix_duration());
}

#[test]
fn default_profile_without_a_tsa_is_unchanged() {
    let fixture = Fixture::new(false, false);
    let original = fixture.original();
    assert!(original.time_stamp.is_none());
    original.verify_es256().unwrap();
    let ca = x509_cert::Certificate::from_der(&original.x5chain[1]).unwrap();
    let ca_curve = key_curve(&ca);
    assert_eq!(ca_curve, const_oid::db::rfc5912::SECP_256_R_1);
}

/// Legacy claim v1 stores a `TimeStampResp` in `sigTst` (C2PA §10.3.2.5.4),
/// countersigning the claim; the token inside it is normalized out.
#[test]
fn legacy_claim_v1_time_stamp_is_normalized_and_covers_the_claim() {
    let fixture = Fixture::with_claim_version(true, true, 1);
    let reader = c2pa_reader(&fixture.signed(), &fixture, &["trust-list.pem", "tsa-trust-list.pem"]);
    let (success, failure) = codes(&reader);
    assert!(failure.is_empty(), "failures: {failure:?}");
    assert!(success.contains(&"timeStamp.trusted".to_string()), "{success:?}");

    let original = fixture.original();
    assert_eq!(original.manifest.claim_label, "c2pa.claim");
    original.verify_es256().unwrap();
    let ts = original.time_stamp.as_ref().unwrap();
    assert_eq!(ts.version, TimeStampVersion::V1);
    assert_ne!(ts.stored, ts.token, "sigTst stores the response, not the bare token");
    assert!(tst_info(&ts.stored).is_err());

    let info = tst_info(&ts.token).unwrap();
    assert!(imprint_matches_sha256(&info, &original.countersignature_structure(TimeStampVersion::V1)));
    assert!(!imprint_matches_sha256(&info, &original.countersignature_structure(TimeStampVersion::V2)));
}

/// The Go CLI (`gnark/cmd/c2pa-zk-gnark`), run with `go run` from `$C2PA_ZK_GO`
/// or `go` on the path.
fn gnark_cli(args: &[&std::ffi::OsStr]) -> std::process::Output {
    let go = std::env::var_os("C2PA_ZK_GO").unwrap_or_else(|| "go".into());
    std::process::Command::new(go)
        .arg("run")
        .arg("./cmd/c2pa-zk-gnark")
        .args(args)
        .current_dir(zk_root().join("gnark"))
        .output()
        .expect("failed to run go (set C2PA_ZK_GO to the go binary)")
}

/// The exported inputs of a real c2pa-signed asset satisfy the gnark
/// statement at its default sizes, and tampered ones do not. Needs Go:
/// `C2PA_ZK_GO=~/.local/go/bin/go cargo test --release --test third_party_fixtures -- --ignored`.
#[test]
#[ignore = "needs Go; compiles the 4.7M-constraint statement (~20 s per check)"]
fn exported_inputs_satisfy_the_gnark_statement() {
    let fixture = Fixture::new(true, true);
    let inputs = fixture.dir.path().join("inputs.json");
    Command::cargo_bin("c2pa-x509-zk-statement-inputs")
        .unwrap()
        .arg("--input")
        .arg(fixture.signed())
        .arg("--trust-list")
        .arg(fixture.pki("trust-list.pem"))
        .arg("--out")
        .arg(&inputs)
        .assert()
        .success();
    let check = |path: &Path| gnark_cli(&["check".as_ref(), "--input".as_ref(), path.as_os_str()]);
    let out = check(&inputs);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let mut json: serde_json::Value = serde_json::from_slice(&std::fs::read(&inputs).unwrap()).unwrap();
    json["time"] = (json["time"].as_u64().unwrap() - 366 * 86400).into();
    let tampered = fixture.dir.path().join("tampered.json");
    std::fs::write(&tampered, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(!check(&tampered).status.success(), "a time before the certificate's validity was accepted");
}

/// Assets without a time stamp, or with a legacy sigTst one, are refused
/// before any proving (THIRD-PARTY-STATEMENT.md, Q6 and Q10).
#[test]
fn statement_inputs_require_a_sigtst2_time_stamp() {
    for (time_stamp, claim_version, expected) in [(false, 2, "no time stamp"), (true, 1, "sigTst (v1)")] {
        let fixture = Fixture::with_claim_version(true, time_stamp, claim_version);
        Command::cargo_bin("c2pa-x509-zk-statement-inputs")
            .unwrap()
            .arg("--input")
            .arg(fixture.signed())
            .arg("--trust-list")
            .arg(fixture.pki("trust-list.pem"))
            .arg("--out")
            .arg(fixture.dir.path().join("inputs.json"))
            .assert()
            .failure()
            .stderr(predicates::str::contains(expected));
    }
}

#[test]
fn statement_inputs_hold_the_signed_parts_and_the_attested_time() {
    let fixture = Fixture::new(true, true);
    let trust = c2pa_x509_zk_demo::TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let inputs = c2pa_x509_zk_demo::third_party::statement_inputs(&fixture.signed(), &trust).unwrap();
    let original = fixture.original();
    let b64 = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
    assert_eq!(inputs.protected, b64(&original.protected));
    assert_eq!(inputs.signature, b64(&original.signature));
    assert_eq!(inputs.public.claim, b64(&original.manifest.claim));
    assert_eq!(inputs.public.issuer_certificate, b64(&std::fs::read(fixture.pki("issuing-ca.der")).unwrap()));
    let info = tst_info(&original.time_stamp.unwrap().token).unwrap();
    assert_eq!(inputs.public.imprint, b64(&info.hashed_message));
    assert_eq!(inputs.public.time, c2pa_x509_zk_demo::third_party::generalized_time_unix(&info.gen_time).unwrap());
}

// ---- Third-party anonymization and verification (E2b) --------------------

use c2pa_x509_zk_demo::third_party::{self, Prover};
use c2pa_x509_zk_demo::zk_signature::{proof_len, ZkSignature, DEFAULT_CURVE};

/// A stand-in for the gnark CLI that reports every proof invalid (exit 1),
/// and a key directory naming a verifying-key hash: reaching the proof check
/// shows every check before it passed.
fn stand_in_prover(dir: &Path, vk: &str) -> Prover {
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(keys.join("keys.json"), serde_json::json!({ "sha256": { "statement.vk": vk } }).to_string()).unwrap();
    let cli = dir.join("gnark-stand-in.sh");
    std::fs::write(&cli, "#!/bin/sh\necho 'proof is INVALID' >&2\nexit 1\n").unwrap();
    std::fs::set_permissions(&cli, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    Prover { cli, keys }
}

/// The mirror fixture with its claim signature replaced in place by a ZK
/// signature holding a placeholder proof, as the anonymizer writes it.
fn replaced_with_placeholder(fixture: &Fixture) -> PathBuf {
    let store = manifest_store(&fixture.signed()).unwrap();
    let manifest = active_manifest(&store).unwrap();
    let original = OriginalSignature::from_manifest(manifest.clone()).unwrap();
    let signature = ZkSignature {
        issuing_chain: vec![std::fs::read(fixture.pki("issuing-ca.der")).unwrap(), std::fs::read(fixture.pki("root.der")).unwrap()],
        issuers: None,
        tsa: None,
        window: None,
        vk_sha256: "00".repeat(32),
        curve: DEFAULT_CURVE.into(),
        time_stamp_token: original.time_stamp.unwrap().token,
        proof: vec![0x5a; proof_len(DEFAULT_CURVE).unwrap()],
    };
    let cose = signature.encode_exact(manifest.cose_sign1.len()).unwrap();
    let output = fixture.dir.path().join("anonymized.png");
    third_party::replace_signature(&fixture.signed(), &output, &store, &manifest, &cose).unwrap();
    output
}

#[test]
fn in_place_replacement_keeps_the_claim_and_its_hard_binding() {
    let fixture = Fixture::new(true, true);
    let output = replaced_with_placeholder(&fixture);
    let (before, after) = (std::fs::read(fixture.signed()).unwrap(), std::fs::read(&output).unwrap());
    assert_eq!(before.len(), after.len());
    let (old_store, new_store) = (manifest_store(&fixture.signed()).unwrap(), manifest_store(&output).unwrap());
    assert_eq!(old_store.len(), new_store.len());
    let (old, new) = (active_manifest(&old_store).unwrap(), active_manifest(&new_store).unwrap());
    assert_eq!(old.claim, new.claim, "the claim is unchanged");
    assert_eq!(old.cose_sign1_range, new.cose_sign1_range);
    assert!(ZkSignature::decode(&new.cose_sign1).is_ok());
    // Everything outside the signature is byte-identical.
    assert_eq!(old_store[..old.cose_sign1_range.start], new_store[..new.cose_sign1_range.start]);
    assert_eq!(old_store[old.cose_sign1_range.end..], new_store[new.cose_sign1_range.end..]);

    // c2pa still validates the claim's assertions and hard binding.
    let success = third_party::c2pa_claim_checks(&output).unwrap();
    assert!(success.contains(&"assertion.dataHash.match".to_string()), "{success:?}");

    // Nothing identifying the signer remains.
    let original = OriginalSignature::from_asset(&fixture.signed()).unwrap();
    let signer = x509_cert::Certificate::from_der(original.signer_certificate().unwrap()).unwrap();
    let spki = signer.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
    for (what, needle) in [
        ("signer certificate", original.signer_certificate().unwrap()),
        ("signer key", spki),
        ("serial number", signer.tbs_certificate.serial_number.as_bytes()),
        ("original protected header", original.protected.as_slice()),
        ("original signature", original.signature.as_slice()),
    ] {
        assert!(!after.windows(needle.len()).any(|w| w == needle), "{what} found in the output");
    }
}

#[test]
fn verifier_checks_trust_time_stamp_and_binding_before_the_proof() {
    let fixture = Fixture::new(true, true);
    let output = replaced_with_placeholder(&fixture);
    let prover = stand_in_prover(fixture.dir.path(), &"00".repeat(32));
    let trust = c2pa_x509_zk_demo::TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let tsa = fixture.pki("tsa-trust-list.pem");
    let verify = |asset: &Path, trust: &c2pa_x509_zk_demo::TrustList, tsa: &Path, prover: &Prover| {
        third_party::verify(asset, trust, Some(tsa), prover, None, None).unwrap_err().to_string()
    };
    assert!(third_party::is_third_party(&output) && !third_party::is_third_party(&fixture.signed()));

    // All checks pass up to the proof, which the stand-in rejects.
    let err = verify(&output, &trust, &tsa, &prover);
    assert!(err.contains("proof does not verify"), "{err}");

    // An untrusted TSA, an untrusted issuing chain, other keys, a changed asset.
    let err = verify(&output, &trust, &fixture.pki("trust-list.pem"), &prover);
    assert!(err.contains("time-stamp token does not verify"), "{err}");
    let other = Fixture::new(true, false);
    let other_trust = c2pa_x509_zk_demo::TrustList::from_file(&other.pki("trust-list.pem")).unwrap();
    let err = verify(&output, &other_trust, &tsa, &prover);
    assert!(!err.contains("proof does not verify"), "an untrusted chain reached the proof: {err}");
    let err = verify(&output, &trust, &tsa, &stand_in_prover(&fixture.dir.path().join("other"), &"11".repeat(32)));
    assert!(err.contains("other keys"), "{err}");

    // Keys for the other curve (here BLS12-381, for a BN254 signature) are refused.
    let bls = stand_in_prover(&fixture.dir.path().join("bls"), &"00".repeat(32));
    std::fs::write(bls.keys.join("keys.json"), serde_json::json!({ "curve": "bls12-381", "sha256": { "statement.vk": "00".repeat(32) } }).to_string()).unwrap();
    let err = verify(&output, &trust, &tsa, &bls);
    assert!(err.contains("keys in") && err.contains("bls12-381"), "{err}");

    // An expected issuer: a mismatch is rejected before the proof, a match reaches it.
    let issuer = c2pa_x509_zk_demo::extract_subject_dn(&std::fs::read(fixture.pki("issuing-ca.der")).unwrap()).unwrap();
    let err = third_party::verify(&output, &trust, Some(&tsa), &prover, Some("CN=Unrelated Expected Issuer"), None).unwrap_err().to_string();
    assert!(err.contains("not the expected"), "{err}");
    let err = third_party::verify(&output, &trust, Some(&tsa), &prover, Some(&issuer), None).unwrap_err().to_string();
    assert!(err.contains("proof does not verify"), "{err}");

    // A signature carrying extra data (here the signer certificate after the
    // proof) is still detected as third-party, and rejected when decoded.
    let store = manifest_store(&output).unwrap();
    let manifest = active_manifest(&store).unwrap();
    let mut signature = ZkSignature::decode(&manifest.cose_sign1).unwrap();
    let signer_cert = OriginalSignature::from_asset(&fixture.signed()).unwrap().signer_certificate().unwrap().to_vec();
    signature.proof.extend_from_slice(&signer_cert);
    let extended = fixture.dir.path().join("extended.png");
    third_party::replace_signature(&output, &extended, &store, &manifest, &signature.encode_exact(manifest.cose_sign1.len()).unwrap()).unwrap();
    assert!(third_party::is_third_party(&extended));
    let err = verify(&extended, &trust, &tsa, &prover);
    assert!(err.contains("the proof is"), "{err}");
    let mut bytes = std::fs::read(&output).unwrap();
    let n = bytes.len();
    bytes[n - 100] ^= 1; // image data, inside the hard binding
    let tampered = fixture.dir.path().join("tampered.png");
    std::fs::write(&tampered, bytes).unwrap();
    let err = verify(&tampered, &trust, &tsa, &prover);
    assert!(err.contains("c2pa validation failed") || err.contains("hard binding"), "{err}");
}

#[test]
fn claims_with_identity_or_ingredients_are_refused() {
    let fixture = Fixture::new(true, true);
    let store = manifest_store(&fixture.signed()).unwrap();
    let claim_with = |label: &str| {
        let value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("created_assertions".into()),
            ciborium::Value::Array(vec![ciborium::Value::Map(vec![(
                ciborium::Value::Text("url".into()),
                ciborium::Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
            )])]),
        )]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    };
    for (label, expected) in [("cawg.identity", "identity assertion"), ("c2pa.ingredient.v3", "ingredient")] {
        let err = third_party::check_claim(&store, &claim_with(label)).unwrap_err().to_string();
        assert!(err.contains(expected), "{label}: {err}");
    }
    let report = third_party::check_claim(&store, &active_manifest(&store).unwrap().claim).unwrap();
    let mut labels = report.assertions.clone();
    labels.sort();
    assert_eq!(labels, ["c2pa.actions.v2", "c2pa.hash.data"]);
    assert!(report.claim_generator.starts_with("c2pa-x509-zk-demo"), "{}", report.claim_generator);
    assert_eq!(report.hard_binding_exclusions.len(), 1, "a PNG excludes only its manifest chunk");
}

/// End to end with real proofs: the anonymizer and verifier CLIs in
/// third-party mode, then rejection of a changed claim. Needs keys from
/// `c2pa-zk-gnark setup` in $C2PA_ZK_KEYS (default target/gnark-keys) and
/// the CLI built to target/c2pa-zk-gnark.
#[test]
#[ignore = "needs gnark keys and CLI; proves for ~1.5 min"]
fn third_party_anonymization_end_to_end() {
    let keys = std::env::var_os("C2PA_ZK_KEYS").map(PathBuf::from).unwrap_or_else(|| zk_root().join("target/gnark-keys"));
    let gnark = zk_root().join("target/c2pa-zk-gnark");
    assert!(keys.join("keys.json").exists() && gnark.exists(), "run c2pa-zk-gnark setup --keys {} first", keys.display());

    let fixture = Fixture::new(true, true);
    let output = fixture.dir.path().join("anonymized.png");
    Command::cargo_bin("c2pa-x509-zk-anonymizer")
        .unwrap()
        .arg("--third-party").arg("--keys").arg(&keys).arg("--gnark").arg(&gnark)
        .arg("--input").arg(fixture.signed()).arg("--output").arg(&output)
        .arg("--trust-list").arg(fixture.pki("trust-list.pem"))
        .assert()
        .success()
        .stdout(predicates::str::contains("replaced in place"));

    let verify_with = |asset: &Path, extra: &[&str]| {
        let mut cmd = Command::cargo_bin("c2pa-x509-zk-verify").unwrap();
        cmd.arg("--input").arg(asset)
            .arg("--trust-list").arg(fixture.pki("trust-list.pem"))
            .arg("--tsa-trust-list").arg(fixture.pki("tsa-trust-list.pem"))
            .arg("--keys").arg(&keys).arg("--gnark").arg(&gnark)
            .args(extra);
        cmd.assert()
    };
    let verify = |asset: &Path| verify_with(asset, &[]);
    verify(&output).success().stdout(predicates::str::contains("Valid"));

    // A claim byte changed in place: c2pa's own checks do not see the claim
    // (its signature is the ZK one), but the proof is bound to it.
    let store = manifest_store(&output).unwrap();
    let manifest = active_manifest(&store).unwrap();
    let bytes = std::fs::read(&output).unwrap();
    let claim_at = bytes.windows(manifest.claim.len()).position(|w| w == manifest.claim.as_slice()).unwrap();
    // Flip a byte inside a text value (the claim generator's name), so the claim still parses.
    let name_at = claim_at + manifest.claim.windows(8).position(|w| w == b"c2pa-x50").unwrap();
    let mut changed = bytes.clone();
    changed[name_at] = b'C';
    let tampered = fixture.dir.path().join("claim-changed.png");
    std::fs::write(&tampered, changed).unwrap();
    verify(&tampered).failure().stderr(predicates::str::contains("proof does not verify"));

    // --issuer is enforced: the issuing CA's DN passes, another is rejected.
    let issuer = c2pa_x509_zk_demo::extract_subject_dn(&std::fs::read(fixture.pki("issuing-ca.der")).unwrap()).unwrap();
    verify_with(&output, &["--issuer", &issuer]).success();
    verify_with(&output, &["--issuer", "CN=Unrelated Expected Issuer"]).failure().stderr(predicates::str::contains("not the expected"));

    // A genuine proof followed by the signer's certificate is rejected.
    let mut signature = ZkSignature::decode(&manifest.cose_sign1).unwrap();
    signature.proof.extend_from_slice(OriginalSignature::from_asset(&fixture.signed()).unwrap().signer_certificate().unwrap());
    let extended = fixture.dir.path().join("extended.png");
    third_party::replace_signature(&output, &extended, &store, &manifest, &signature.encode_exact(manifest.cose_sign1.len()).unwrap()).unwrap();
    verify(&extended).failure().stderr(predicates::str::contains("the proof is"));
}

/// R2: a real signed asset, end to end. Not committed (third-party content):
/// point C2PA_R2_ASSET at it, and C2PA_R2_TRUST_LIST / C2PA_R2_TSA_TRUST_LIST
/// at the trust lists it is signed under (for example the official C2PA
/// lists). Needs keys and the gnark CLI as for the end-to-end test. Checks
/// that the asset anonymizes and verifies, that no identifier of the signer
/// remains, and that a changed claim is rejected by the proof.
#[test]
#[ignore = "needs a real signed asset (C2PA_R2_ASSET, C2PA_R2_TRUST_LIST, C2PA_R2_TSA_TRUST_LIST), gnark keys, and the CLI"]
fn real_asset_end_to_end() {
    let var = |name: &str| PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name}")));
    let (asset, trust_list, tsa_trust_list) = (var("C2PA_R2_ASSET"), var("C2PA_R2_TRUST_LIST"), var("C2PA_R2_TSA_TRUST_LIST"));
    let keys = std::env::var_os("C2PA_ZK_KEYS").map(PathBuf::from).unwrap_or_else(|| zk_root().join("target/gnark-keys"));
    let gnark = zk_root().join("target/c2pa-zk-gnark");
    let dir = tempdir().unwrap();
    let ext = asset.extension().unwrap().to_str().unwrap();
    let output = dir.path().join(format!("anonymized.{ext}"));

    Command::cargo_bin("c2pa-x509-zk-anonymizer")
        .unwrap()
        .arg("--third-party").arg("--keys").arg(&keys).arg("--gnark").arg(&gnark)
        .arg("--input").arg(&asset).arg("--output").arg(&output).arg("--trust-list").arg(&trust_list)
        .assert()
        .success();
    let verify = |path: &Path| {
        let mut cmd = Command::cargo_bin("c2pa-x509-zk-verify").unwrap();
        cmd.arg("--input").arg(path).arg("--trust-list").arg(&trust_list).arg("--tsa-trust-list").arg(&tsa_trust_list)
            .arg("--keys").arg(&keys).arg("--gnark").arg(&gnark);
        cmd.assert()
    };
    verify(&output).success().stdout(predicates::str::contains("Valid"));
    assert_eq!(std::fs::metadata(&asset).unwrap().len(), std::fs::metadata(&output).unwrap().len());

    // No identifier of the signer remains (the original has them all).
    let original = OriginalSignature::from_asset(&asset).unwrap();
    let signer = x509_cert::Certificate::from_der(original.signer_certificate().unwrap()).unwrap();
    let after = std::fs::read(&output).unwrap();
    let before = std::fs::read(&asset).unwrap();
    for (what, needle) in [
        ("signer certificate", original.signer_certificate().unwrap()),
        ("signer key", signer.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes()),
        ("serial number", signer.tbs_certificate.serial_number.as_bytes()),
        ("original protected header", original.protected.as_slice()),
        ("original signature", original.signature.as_slice()),
    ] {
        assert!(before.windows(needle.len()).any(|w| w == needle), "control: {what} not in the original");
        assert!(!after.windows(needle.len()).any(|w| w == needle), "{what} found in the output");
    }

    // A changed claim byte (inside the claim's bytes in the file) is rejected by the proof.
    let claim = &original.manifest.claim;
    let at = after.windows(claim.len()).position(|w| w == claim.as_slice()).expect("claim in the output");
    // The claim generator's name: the text value after the CBOR key "name"
    // (64 6E 61 6D 65), so the claim stays well-formed for c2pa.
    let key = claim.windows(5).position(|w| w == b"\x64name").expect("a name field in the claim");
    let value = match claim[key + 5] {
        0x60..=0x77 => key + 6,
        0x78 => key + 7,
        other => panic!("unexpected CBOR header {other:#x} for the name"),
    };
    let mut changed = after.clone();
    changed[at + value] ^= 0x20; // flip a letter's case
    let tampered = dir.path().join(format!("tampered.{ext}"));
    std::fs::write(&tampered, changed).unwrap();
    verify(&tampered).failure().stderr(predicates::str::contains("proof does not verify"));
}

// ---- H4: the hidden issuer ------------------------------------------------------

use c2pa_x509_zk_demo::third_party::{IssuerPolicy, Snapshot};
use c2pa_x509_zk_demo::zk_signature::IssuerTreeRef;
use c2pa_x509_zk_demo::TrustList;

/// A stand-in CLI for the hidden-issuer statement: `tree` gives the issuers
/// file's SHA-256 as the root (deterministic, as the real tree is), `verify`
/// reports every proof invalid. Reaching the proof check shows that every
/// check before it passed.
fn hidden_stand_in(dir: &Path) -> Prover {
    stand_in_for(dir, "hidden-issuer")
}

/// The stand-in CLI with keys for the given statement variant.
fn stand_in_for(dir: &Path, variant: &str) -> Prover {
    let keys = dir.join(format!("{variant}-keys"));
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(keys.join("keys.json"), serde_json::json!({ "variant": variant, "sha256": { "statement.vk": "00".repeat(32) } }).to_string()).unwrap();
    let cli = dir.join(format!("gnark-{variant}-stand-in.sh"));
    std::fs::write(&cli, r#"#!/bin/sh
case "$1" in
  tree)
    role=issuer
    while [ $# -gt 0 ]; do [ "$1" = "--issuers" ] && f="$2"; [ "$1" = "--role" ] && role="$2"; shift; done
    root=$( (cat "$f"; echo "$role") | sha256sum | cut -c1-64 | sed 's/^0*//')
    n=$(grep -c 'BEGIN CERTIFICATE' "$f")
    printf '{"role": "%s", "root": "%s", "entries": [' "$role" "$root"; i=1; while [ $i -le $n ]; do [ $i -gt 1 ] && printf ','; printf '{}'; i=$((i+1)); done; printf ']}
' ;;
  verify) echo 'proof is INVALID' >&2; exit 1 ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#).unwrap();
    std::fs::set_permissions(&cli, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    Prover { cli, keys }
}

/// The mirror fixture anonymized with the issuer hidden, as the anonymizer
/// writes it, with a placeholder proof: the root of the tree over `list`'s
/// eligible issuers, named `name`.
fn hidden_with_placeholder(fixture: &Fixture, prover: &Prover, list: &Path, name: &str) -> PathBuf {
    let store = manifest_store(&fixture.signed()).unwrap();
    let manifest = active_manifest(&store).unwrap();
    let original = OriginalSignature::from_manifest(manifest.clone()).unwrap();
    let tree = third_party::issuer_tree(&TrustList::from_file(list).unwrap(), prover).unwrap();
    let signature = ZkSignature {
        issuing_chain: vec![],
        issuers: Some(IssuerTreeRef { root: tree.root, list: name.into() }),
        tsa: None,
        window: None,
        vk_sha256: "00".repeat(32),
        curve: DEFAULT_CURVE.into(),
        time_stamp_token: original.time_stamp.unwrap().token,
        proof: vec![0x5a; proof_len(DEFAULT_CURVE).unwrap()],
    };
    let cose = signature.encode_exact(manifest.cose_sign1.len()).unwrap();
    let output = fixture.dir.path().join(format!("hidden-{name}.png"));
    third_party::replace_signature(&fixture.signed(), &output, &store, &manifest, &cose).unwrap();
    output
}

fn policy(snapshots: Vec<(&str, PathBuf, u64, Option<u64>)>) -> IssuerPolicy {
    IssuerPolicy { tsa_snapshots: Vec::new(), max_time_window: None, snapshots: snapshots.into_iter().map(|(name, trust_list, from, until)| Snapshot { name: name.into(), trust_list, from, until }).collect() }
}

/// The verifier's issuer policy decides, never the asset: a root must be one
/// the verifier built from an approved snapshot whose interval contains the
/// attested time, and the asset's list name must name that snapshot.
#[test]
fn hidden_issuer_verification_follows_the_verifiers_policy() {
    let fixture = Fixture::new(true, true);
    let other = Fixture::new(true, true);
    let prover = hidden_stand_in(fixture.dir.path());
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let tsa = fixture.pki("tsa-trust-list.pem");
    let list = fixture.pki("trust-list.pem");
    let asset = hidden_with_placeholder(&fixture, &prover, &list, "fixture-list");
    let t = third_party::statement_inputs(&fixture.signed(), &trust).unwrap().public.time;
    let verify = |asset: &Path, policy: Option<&IssuerPolicy>, expected: Option<&str>| {
        third_party::verify(asset, &trust, Some(&tsa), &prover, expected, policy).unwrap_err().to_string()
    };

    // Every check passes up to the proof (which the stand-in reports invalid).
    let approved = policy(vec![("fixture-list", list.clone(), t, None)]);
    let err = verify(&asset, Some(&approved), None);
    assert!(err.contains("the proof does not verify"), "{err}");

    for (name, policy, expected, reason) in [
        ("no policy", None, None, "needs an issuer policy"),
        ("an expected issuer", Some(approved.clone()), Some("CN=Anything"), "an expected issuer cannot be checked"),
        ("another list only", Some(policy(vec![("fixture-list", other.pki("trust-list.pem"), 0, None)])), None, "not that of any snapshot"),
        ("t before the snapshot applied", Some(policy(vec![("fixture-list", list.clone(), t + 1, None)])), None, "did not apply at the attested time"),
        ("t after the snapshot was replaced", Some(policy(vec![("fixture-list", list.clone(), 0, Some(t))])), None, "did not apply at the attested time"),
        ("the list name of another snapshot", Some(policy(vec![("another-name", list.clone(), 0, None)])), None, "names the trust list"),
    ] {
        let err = verify(&asset, policy.as_ref(), expected);
        assert!(err.contains(reason), "{name}: {err}");
    }

    // A subset is approved only as its own snapshot: an asset proved against
    // the subset's root (here, the issuing CA alone) is accepted under a
    // policy approving that subset, not under one approving the full list.
    let subset = fixture.pki("issuing-ca.pem");
    let subset_asset = hidden_with_placeholder(&fixture, &prover, &subset, "fixture-subset");
    let err = verify(&subset_asset, Some(&policy(vec![("fixture-list", list.clone(), 0, None)])), None);
    assert!(err.contains("not that of any snapshot"), "{err}");
    let err = verify(&subset_asset, Some(&policy(vec![("fixture-list", list.clone(), 0, None), ("fixture-subset", subset.clone(), 0, None)])), None);
    assert!(err.contains("the proof does not verify"), "{err}");

    // Keys for the disclosed statement refuse a hidden-issuer asset.
    let disclosed = stand_in_prover(fixture.dir.path(), &"00".repeat(32));
    let err = third_party::verify(&asset, &trust, Some(&tsa), &disclosed, None, Some(&approved)).unwrap_err().to_string();
    assert!(err.contains("keys in") && err.contains("disclosed statement"), "{err}");
}

/// Both trees can be built in one working directory (PR #40 review): each
/// purpose writes its own eligible-issuers file, and each file keeps its own
/// certificates after the other tree is built.
#[test]
fn both_purpose_trees_coexist_in_one_directory() {
    use c2pa_x509_zk_demo::trust::Purpose;
    let fixture = Fixture::new(true, true);
    let prover = hidden_stand_in(fixture.dir.path());
    let dir = tempfile::tempdir().unwrap();
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let tsa_trust = TrustList::from_file(&fixture.pki("tsa-trust-list.pem")).unwrap();
    let (issuer_tree, issuer_pem) = third_party::purpose_tree(&trust, Purpose::ClaimSigning, &prover, dir.path()).unwrap();
    let issuer_contents = std::fs::read(&issuer_pem).unwrap();
    let (tsa_tree, tsa_pem) = third_party::purpose_tree(&tsa_trust, Purpose::TimeStamping, &prover, dir.path()).unwrap();
    assert_ne!(issuer_pem, tsa_pem);
    assert_eq!(std::fs::read(&issuer_pem).unwrap(), issuer_contents, "the issuer list was overwritten");
    let certs = |path: &Path| TrustList::from_file(path).unwrap().anchors;
    let (issuers, tsas) = (certs(&issuer_pem), certs(&tsa_pem));
    let read = |name: &str| std::fs::read(fixture.pki(name)).unwrap();
    assert!(issuers.contains(&read("issuing-ca.der")) && !issuers.contains(&read("tsa-ca.der")));
    assert!(tsas.contains(&read("tsa-ca.der")) && !tsas.contains(&read("issuing-ca.der")));
    // Each returned file still builds the root returned with it.
    assert_eq!(third_party::purpose_tree(&TrustList { anchors: issuers, skipped: 0 }, Purpose::ClaimSigning, &prover, tempfile::tempdir().unwrap().path()).unwrap().0.root, issuer_tree.root);
    assert_eq!(third_party::purpose_tree(&TrustList { anchors: tsas, skipped: 0 }, Purpose::TimeStamping, &prover, tempfile::tempdir().unwrap().path()).unwrap().0.root, tsa_tree.root);
}

/// The mirror fixture's time stamp has the real profile (I6,
/// HIDING-THE-TIME-STAMP.md): a P-256 TSA certificate issued by a listed
/// P-384 TSA CA, both carried in the token, the root not; the TSA CA is
/// eligible for time stamping, not for claim signing.
#[test]
fn mirror_time_stamp_has_the_real_profile() {
    use c2pa_x509_zk_demo::trust::{eligible_issuers, Purpose};
    let fixture = Fixture::new(true, true);
    let token = fixture.original().time_stamp.unwrap().token;
    let has = |name: &str| {
        let cert = std::fs::read(fixture.pki(name)).unwrap();
        token.windows(cert.len()).any(|w| w == cert.as_slice())
    };
    assert!(has("tsa.der") && has("tsa-ca.der") && !has("tsa-root.der"));

    // The algorithms: a P-256 TSA key, a P-384 TSA CA key, ECDSA-SHA384 between them.
    let parse = |name: &str| x509_cert::Certificate::from_der(&std::fs::read(fixture.pki(name)).unwrap()).unwrap();
    let (tsa_cert, tsa_ca_cert) = (parse("tsa.der"), parse("tsa-ca.der"));
    assert_eq!(key_curve(&tsa_cert), const_oid::db::rfc5912::SECP_256_R_1);
    assert_eq!(key_curve(&tsa_ca_cert), const_oid::db::rfc5912::SECP_384_R_1);
    assert_eq!(tsa_cert.signature_algorithm.oid, const_oid::db::rfc5912::ECDSA_WITH_SHA_384);

    let tsa_ca = std::fs::read(fixture.pki("tsa-ca.der")).unwrap();
    let tsa_trust = TrustList::from_file(&fixture.pki("tsa-trust-list.pem")).unwrap();
    assert!(tsa_trust.is_anchor(&tsa_ca));
    assert!(eligible_issuers(&tsa_trust, Purpose::TimeStamping).0.contains(&tsa_ca));
    assert!(!eligible_issuers(&tsa_trust, Purpose::ClaimSigning).0.contains(&tsa_ca));
}

/// A policy file's snapshots reject unknown fields: a misspelled `until`
/// must not turn an expiring approval into an indefinite one. Omitting
/// `until` on purpose is still accepted.
#[test]
fn issuer_policy_rejects_unknown_snapshot_fields() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, snapshot: serde_json::Value| {
        let path = dir.path().join(name);
        std::fs::write(&path, serde_json::json!({ "snapshots": [snapshot] }).to_string()).unwrap();
        path
    };
    let typo = write("typo.json", serde_json::json!({ "name": "historical-list", "trust_list": "list.pem", "from": 0, "untill": 100 }));
    let err = format!("{:#}", IssuerPolicy::from_file(&typo).unwrap_err());
    assert!(err.contains("untill"), "{err}");
    let current = write("current.json", serde_json::json!({ "name": "current-list", "trust_list": "list.pem", "from": 0 }));
    assert!(IssuerPolicy::from_file(&current).unwrap().snapshots[0].until.is_none());
}

/// Snapshots with the same root (for example, lists differing only in
/// certificates the tree leaves out) and overlapping periods: the asset is
/// accepted under the one it names, in either order, and refused if it names
/// neither.
#[test]
fn issuer_policy_does_not_depend_on_snapshot_order() {
    let fixture = Fixture::new(true, true);
    let prover = hidden_stand_in(fixture.dir.path());
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let tsa = fixture.pki("tsa-trust-list.pem");
    let list = fixture.pki("trust-list.pem");
    let asset = hidden_with_placeholder(&fixture, &prover, &list, "fixture-list");
    let verify = |policy: &IssuerPolicy| third_party::verify(&asset, &trust, Some(&tsa), &prover, None, Some(policy)).unwrap_err().to_string();
    let named = |a: &str, b: &str| policy(vec![(a, list.clone(), 0, None), (b, list.clone(), 0, None)]);
    for policy in [named("other-approved-name", "fixture-list"), named("fixture-list", "other-approved-name")] {
        let err = verify(&policy);
        assert!(err.contains("the proof does not verify"), "{err}");
    }
    let err = verify(&named("other-approved-name", "yet-another-name"));
    assert!(err.contains("names the trust list"), "{err}");
}

/// Without x5chain, c2pa-rs does not read the manifest; the verifier still
/// checks the claim's assertions and hard binding, on a copy carrying the
/// placeholder certificate (HIDING-THE-ISSUER.md, I5).
#[test]
fn hidden_issuer_keeps_the_c2pa_claim_checks() {
    let fixture = Fixture::new(true, true);
    let prover = hidden_stand_in(fixture.dir.path());
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let tsa = fixture.pki("tsa-trust-list.pem");
    let list = fixture.pki("trust-list.pem");
    let asset = hidden_with_placeholder(&fixture, &prover, &list, "fixture-list");
    let approved = policy(vec![("fixture-list", list, 0, None)]);

    // Directly, c2pa cannot read the asset at all.
    let err = third_party::c2pa_claim_checks(&asset).unwrap_err().to_string();
    assert!(err.contains("signing certificate chain"), "{err}");

    // A byte of the image changed (inside the PNG's image data, covered by
    // the hard binding): the placeholder copy's c2pa check catches it before
    // the proof.
    let mut bytes = std::fs::read(&asset).unwrap();
    let idat = bytes.windows(4).position(|w| w == b"IDAT").unwrap();
    bytes[idat + 40] ^= 1;
    let changed = fixture.dir.path().join("hidden-changed.png");
    std::fs::write(&changed, bytes).unwrap();
    let err = third_party::verify(&changed, &trust, Some(&tsa), &prover, None, Some(&approved)).unwrap_err().to_string();
    assert!(err.contains("c2pa") && !err.contains("the proof does not verify"), "{err}");
    let err = third_party::verify(&asset, &trust, Some(&tsa), &prover, None, Some(&approved)).unwrap_err().to_string();
    assert!(err.contains("the proof does not verify"), "intact asset: {err}");

    // Nothing of the CA chain is written: neither the issuing CA nor the root.
    let after = std::fs::read(&asset).unwrap();
    for name in ["issuing-ca.der", "root.der"] {
        let cert = std::fs::read(fixture.pki(name)).unwrap();
        assert!(!after.windows(cert.len()).any(|w| w == cert.as_slice()), "{name} in the output");
    }
}

// ---- I6: the hidden time stamp ------------------------------------------------

/// The mirror fixture anonymized with the issuer and the time stamp hidden,
/// as the anonymizer writes it, with a placeholder proof: the roots of the
/// trees over `list` (claim signing) and `tsa_list` (time stamping), named
/// `name` and `tsa_name`, and the UTC day's window.
fn hidden_all_with_placeholder(fixture: &Fixture, prover: &Prover, list: &Path, tsa_list: &Path, name: &str, tsa_name: &str) -> (PathBuf, (u64, u64)) {
    use c2pa_x509_zk_demo::trust::Purpose;
    let store = manifest_store(&fixture.signed()).unwrap();
    let manifest = active_manifest(&store).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let issuers = third_party::purpose_tree(&TrustList::from_file(list).unwrap(), Purpose::ClaimSigning, prover, dir.path()).unwrap().0;
    let tsa = third_party::purpose_tree(&TrustList::from_file(tsa_list).unwrap(), Purpose::TimeStamping, prover, dir.path()).unwrap().0;
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let t = third_party::statement_inputs(&fixture.signed(), &trust).unwrap().public.time;
    let window = (t - t % 86_400, t - t % 86_400 + 86_400);
    let signature = ZkSignature {
        issuing_chain: vec![],
        issuers: Some(IssuerTreeRef { root: issuers.root, list: name.into() }),
        tsa: Some(IssuerTreeRef { root: tsa.root, list: tsa_name.into() }),
        window: Some(window),
        vk_sha256: "00".repeat(32),
        curve: DEFAULT_CURVE.into(),
        time_stamp_token: Vec::new(),
        proof: vec![0x5a; proof_len(DEFAULT_CURVE).unwrap()],
    };
    let cose = signature.encode_exact(manifest.cose_sign1.len()).unwrap();
    let output = fixture.dir.path().join(format!("hidden-all-{name}-{tsa_name}.png"));
    third_party::replace_signature(&fixture.signed(), &output, &store, &manifest, &cose).unwrap();
    (output, window)
}

type Snap<'a> = (&'a str, PathBuf, u64, Option<u64>);

fn policy_all(snapshots: Vec<Snap>, tsa_snapshots: Vec<Snap>, max_time_window: Option<u64>) -> IssuerPolicy {
    let snap = |v: Vec<Snap>| v.into_iter().map(|(name, trust_list, from, until)| Snapshot { name: name.into(), trust_list, from, until }).collect();
    IssuerPolicy { snapshots: snap(snapshots), tsa_snapshots: snap(tsa_snapshots), max_time_window }
}

/// The verifier's policy for hidden time stamps (HIDING-THE-TIME-STAMP.md,
/// T3-T4): both roots approved by the verifier, each built for its purpose,
/// from snapshots containing the whole window; the asset's names are hints.
#[test]
fn hidden_all_verification_follows_the_policy() {
    let fixture = Fixture::new(true, true);
    let other = Fixture::new(true, true);
    let prover = stand_in_for(fixture.dir.path(), "hidden-all");
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let (list, tsa_list) = (fixture.pki("trust-list.pem"), fixture.pki("tsa-trust-list.pem"));
    let (asset, (t1, t2)) = hidden_all_with_placeholder(&fixture, &prover, &list, &tsa_list, "fixture-list", "fixture-tsa");
    // No TSA trust list is given: the time stamp is checked in the proof.
    let verify = |policy: Option<&IssuerPolicy>| third_party::verify(&asset, &trust, None, &prover, None, policy).unwrap_err().to_string();
    let issuers = || vec![("fixture-list", list.clone(), 0, None)];

    let approved = policy_all(issuers(), vec![("fixture-tsa", tsa_list.clone(), 0, None)], None);
    let err = verify(Some(&approved));
    assert!(err.contains("the proof does not verify"), "{err}");

    for (name, policy, reason) in [
        ("no policy", None, "needs an issuer policy"),
        ("no TSA snapshots", Some(policy_all(issuers(), vec![], None)), "approves no TSA snapshot"),
        // The signer list, filtered and hashed for time stamping, is another root.
        ("a TSA snapshot of the signer list", Some(policy_all(issuers(), vec![("fixture-tsa", list.clone(), 0, None)], None)), "TSA tree root is not that of any snapshot"),
        ("another PKI's TSA list", Some(policy_all(issuers(), vec![("fixture-tsa", other.pki("tsa-trust-list.pem"), 0, None)], None)), "TSA tree root is not that of any snapshot"),
        // The issuer root is checked against issuer snapshots only.
        ("the issuer list as a TSA snapshot and the TSA list as an issuer one", Some(policy_all(vec![("fixture-list", tsa_list.clone(), 0, None)], vec![("fixture-tsa", list.clone(), 0, None)], None)), "issuer tree root is not that of any snapshot"),
        ("a TSA snapshot from after t1", Some(policy_all(issuers(), vec![("fixture-tsa", tsa_list.clone(), t1 + 1, None)], None)), "did not apply at the attested time window"),
        ("a TSA snapshot replaced inside the window", Some(policy_all(issuers(), vec![("fixture-tsa", tsa_list.clone(), 0, Some(t2 - 1))], None)), "did not apply at the attested time window"),
        ("an issuer snapshot replaced inside the window", Some(policy_all(vec![("fixture-list", list.clone(), 0, Some(t2 - 1))], vec![("fixture-tsa", tsa_list.clone(), 0, None)], None)), "did not apply at the attested time window"),
        ("a TSA list of another name", Some(policy_all(issuers(), vec![("another-tsa", tsa_list.clone(), 0, None)], None)), "names the TSA trust list"),
        ("a maximum window of an hour", Some(policy_all(issuers(), vec![("fixture-tsa", tsa_list.clone(), 0, None)], Some(3600))), "longer than the policy's maximum"),
    ] {
        let err = verify(policy.as_ref());
        assert!(err.contains(reason), "{name}: {err}");
    }

    // Windows ending exactly at a snapshot's end are covered (half-open).
    let at_expiry = policy_all(vec![("fixture-list", list.clone(), 0, Some(t2))], vec![("fixture-tsa", tsa_list.clone(), t1, Some(t2))], Some(86_400));
    let err = verify(Some(&at_expiry));
    assert!(err.contains("the proof does not verify"), "a window ending at the snapshots' end: {err}");

    // Keys for the other statements refuse a hidden-all asset.
    for variant in ["hidden-issuer", "disclosed"] {
        let keys = stand_in_for(fixture.dir.path(), variant);
        let err = third_party::verify(&asset, &trust, None, &keys, None, Some(&approved)).unwrap_err().to_string();
        assert!(err.contains("the statement hiding the issuer and the time stamp, but the keys"), "{variant}: {err}");
    }
}

/// The output carries no token: neither the token's bytes, the TSA's
/// certificates, nor its serial number; the c2pa checks still run on the
/// placeholder copy.
#[test]
fn hidden_all_output_carries_no_token() {
    let fixture = Fixture::new(true, true);
    let prover = stand_in_for(fixture.dir.path(), "hidden-all");
    let (asset, _) = hidden_all_with_placeholder(&fixture, &prover, &fixture.pki("trust-list.pem"), &fixture.pki("tsa-trust-list.pem"), "fixture-list", "fixture-tsa");
    let token = fixture.original().time_stamp.unwrap().token;
    let after = std::fs::read(&asset).unwrap();
    let mut needles = vec![("the token", token.clone())];
    for name in ["tsa.der", "tsa-ca.der", "tsa-root.der", "issuing-ca.der", "root.der"] {
        needles.push((name, std::fs::read(fixture.pki(name)).unwrap()));
    }
    // The token's TSTInfo carries the serial number; its first 40 bytes do.
    let tst = &token[token.len() / 2..token.len() / 2 + 40];
    needles.push(("a part of the token", tst.to_vec()));
    for (what, needle) in needles {
        assert!(!after.windows(needle.len()).any(|w| w == needle.as_slice()), "{what} found in the output");
    }
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let approved = policy_all(vec![("fixture-list", fixture.pki("trust-list.pem"), 0, None)], vec![("fixture-tsa", fixture.pki("tsa-trust-list.pem"), 0, None)], None);
    let mut bytes = after.clone();
    let idat = bytes.windows(4).position(|w| w == b"IDAT").unwrap();
    bytes[idat + 40] ^= 1;
    let changed = fixture.dir.path().join("hidden-all-changed.png");
    std::fs::write(&changed, bytes).unwrap();
    let err = third_party::verify(&changed, &trust, None, &prover, None, Some(&approved)).unwrap_err().to_string();
    assert!(err.contains("c2pa") && !err.contains("the proof does not verify"), "{err}");
}

/// The anonymizer's refusals with the time stamp hidden, all before proving.
#[test]
fn hidden_all_anonymizer_refusals() {
    use c2pa_x509_zk_demo::third_party::HideTimeStamp;
    let fixture = Fixture::new(true, true);
    let all = stand_in_for(fixture.dir.path(), "hidden-all");
    let issuer_only = hidden_stand_in(fixture.dir.path());
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let hide = |tsa_list: &str| HideTimeStamp { tsa_trust: TrustList::from_file(&fixture.pki(tsa_list)).unwrap(), list: "fixture-tsa".into(), window: 86_400 };
    let out = fixture.dir.path().join("out-all.png");
    let anonymize = |prover: &Prover, hide_issuer: Option<&str>, h: Option<&HideTimeStamp>| third_party::anonymize(&fixture.signed(), &out, &trust, prover, hide_issuer, h).unwrap_err().to_string();

    let err = anonymize(&all, Some("fixture-list"), None);
    assert!(err.contains("use --hide-issuer and --hide-time-stamp"), "{err}");
    let err = anonymize(&issuer_only, Some("fixture-list"), Some(&hide("tsa-trust-list.pem")));
    assert!(err.contains("needs keys for the hidden-all statement"), "{err}");
    let err = anonymize(&all, None, Some(&hide("tsa-trust-list.pem")));
    assert!(err.contains("needs --hide-issuer too"), "{err}");
    // The TSA CA must itself be listed (the root alone is not enough), and
    // eligible for time stamping (the signer list's CAs are not the TSA's issuers).
    for list in ["tsa-root.pem", "trust-list.pem"] {
        let err = anonymize(&all, Some("fixture-list"), Some(&hide(list)));
        assert!(err.contains("not issued by a CA itself on the TSA trust list"), "{list}: {err}");
    }
    assert!(!out.exists());

    // Window lengths.
    use c2pa_x509_zk_demo::third_party::parse_window;
    assert_eq!(parse_window("1d").unwrap(), 86_400);
    assert_eq!(parse_window("1h").unwrap(), 3600);
    assert_eq!(parse_window("1s").unwrap(), 1);
    assert_eq!(parse_window("90").unwrap(), 90);
    assert_eq!(parse_window("366d").unwrap(), 366 * 86_400);
    for bad in ["0", "0d", "1w", "", "d", "-1d", "367d", "31622401", "307445734561825861m", "18446744073709551615d", "99999999999999999999"] {
        assert!(parse_window(bad).is_err(), "{bad:?}");
    }

    // The public API checks the window too (PR #41 review): no panic, a refusal.
    for window in [0, c2pa_x509_zk_demo::third_party::MAX_TIME_WINDOW + 1, u64::MAX] {
        let h = HideTimeStamp { window, ..hide("tsa-trust-list.pem") };
        let err = anonymize(&all, Some("fixture-list"), Some(&h));
        assert!(err.contains("window"), "window {window}: {err}");
    }
}

/// I6 end to end with real proofs: anonymize with the issuer and the time
/// stamp hidden, verify under a policy with TSA snapshots, and check that no
/// token or CA certificate is written. Needs hidden-all keys (`c2pa-zk-gnark
/// setup --statement hidden-all`) in $C2PA_ZK_HIDDEN_ALL_KEYS (default
/// target/gnark-keys-hidden-all) and the CLI.
#[test]
#[ignore = "needs hidden-all gnark keys and the CLI; proves for ~2 min"]
fn hidden_all_end_to_end() {
    let keys = std::env::var_os("C2PA_ZK_HIDDEN_ALL_KEYS").map(PathBuf::from).unwrap_or_else(|| zk_root().join("target/gnark-keys-hidden-all"));
    let gnark = zk_root().join("target/c2pa-zk-gnark");
    assert!(keys.join("keys.json").exists() && gnark.exists(), "run c2pa-zk-gnark setup --statement hidden-all --keys {} first", keys.display());

    let fixture = Fixture::new(true, true);
    let other = Fixture::new(true, true);
    let output = fixture.dir.path().join("anonymized-all.png");
    Command::cargo_bin("c2pa-x509-zk-anonymizer")
        .unwrap()
        .arg("--third-party").arg("--hide-issuer").arg("fixture-list")
        .arg("--hide-time-stamp").arg("fixture-tsa").arg("--tsa-trust-list").arg(fixture.pki("tsa-trust-list.pem"))
        .arg("--keys").arg(&keys).arg("--gnark").arg(&gnark)
        .arg("--input").arg(fixture.signed()).arg("--output").arg(&output)
        .arg("--trust-list").arg(fixture.pki("trust-list.pem"))
        .assert()
        .success()
        .stdout(predicates::str::contains("hidden among the 2 eligible TSA CAs of fixture-tsa"));

    let write_policy = |name: &str, tsa_list: PathBuf| {
        let path = fixture.dir.path().join(format!("policy-all-{name}.json"));
        std::fs::write(&path, serde_json::json!({
            "snapshots": [{ "name": "fixture-list", "trust_list": fixture.pki("trust-list.pem"), "from": 0 }],
            "tsa_snapshots": [{ "name": "fixture-tsa", "trust_list": tsa_list, "from": 0 }],
            "max_time_window": 86_400,
        }).to_string()).unwrap();
        path
    };
    let approved = write_policy("approved", fixture.pki("tsa-trust-list.pem"));
    let unrelated = write_policy("unrelated", other.pki("tsa-trust-list.pem"));
    let verify = |asset: &Path, policy: &Path| {
        // No --tsa-trust-list: the time stamp is checked in the proof.
        Command::cargo_bin("c2pa-x509-zk-verify").unwrap()
            .arg("--input").arg(asset)
            .arg("--trust-list").arg(fixture.pki("trust-list.pem"))
            .arg("--keys").arg(&keys).arg("--gnark").arg(&gnark)
            .arg("--issuer-policy").arg(policy)
            .assert()
    };
    verify(&output, &approved).success().stdout(predicates::str::contains("Valid")).stdout(predicates::str::contains("the exact time is not disclosed"));
    verify(&output, &unrelated).failure().stderr(predicates::str::contains("TSA tree root is not that of any snapshot"));

    // Nothing of the token, the TSA, the CAs, or the signer is in the output.
    let after = std::fs::read(&output).unwrap();
    let original = fixture.original();
    let token = original.time_stamp.clone().unwrap().token;
    let mut needles = vec![("the token", token.clone()), ("the signer certificate", original.signer_certificate().unwrap().to_vec()), ("the original signature", original.signature.clone())];
    for name in ["tsa.der", "tsa-ca.der", "tsa-root.der", "issuing-ca.der", "root.der"] {
        needles.push((name, std::fs::read(fixture.pki(name)).unwrap()));
    }
    for (what, needle) in needles {
        assert!(!after.windows(needle.len()).any(|w| w == needle.as_slice()), "{what} found in the output");
    }

    // A changed claim byte is rejected by the proof.
    let store = manifest_store(&output).unwrap();
    let manifest = active_manifest(&store).unwrap();
    let claim_at = after.windows(manifest.claim.len()).position(|w| w == manifest.claim.as_slice()).unwrap();
    let name_at = claim_at + manifest.claim.windows(8).position(|w| w == b"c2pa-x50").unwrap();
    let mut changed = after.clone();
    changed[name_at] = b'C';
    let tampered = fixture.dir.path().join("hidden-all-claim-changed.png");
    std::fs::write(&tampered, changed).unwrap();
    verify(&tampered, &approved).failure().stderr(predicates::str::contains("proof does not verify"));
}

/// The anonymizer's refusals with the issuer hidden, all before proving.
#[test]
fn hidden_issuer_anonymizer_refusals() {
    let fixture = Fixture::new(true, true);
    let hidden = hidden_stand_in(fixture.dir.path());
    let disclosed = stand_in_prover(fixture.dir.path(), &"00".repeat(32));
    let trust = TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let out = fixture.dir.path().join("out.png");
    let anonymize = |trust: &TrustList, prover: &Prover, hide: Option<&str>| third_party::anonymize(&fixture.signed(), &out, trust, prover, hide, None).unwrap_err().to_string();

    let err = anonymize(&trust, &disclosed, Some("fixture-list"));
    assert!(err.contains("needs keys for the hidden-issuer statement"), "{err}");
    let err = anonymize(&trust, &hidden, None);
    assert!(err.contains("use --hide-issuer"), "{err}");
    // The issuing CA must itself be on the list (I2): with the root alone as
    // the trust list, the path has two certificates.
    let root_only = TrustList::from_file(&fixture.pki("root.pem")).unwrap();
    let err = anonymize(&root_only, &hidden, Some("root-only"));
    assert!(err.contains("not itself on the trust list"), "{err}");
    assert!(!out.exists());
}

/// H4 end to end with real proofs: anonymize with the issuer hidden, verify
/// under an issuer policy, and check that no CA certificate is written. Needs
/// hidden-issuer keys (`c2pa-zk-gnark setup --statement hidden-issuer`) in
/// $C2PA_ZK_HIDDEN_KEYS (default target/gnark-keys-hidden) and the CLI.
#[test]
#[ignore = "needs hidden-issuer gnark keys and the CLI; proves for ~1.5 min"]
fn hidden_issuer_end_to_end() {
    let keys = std::env::var_os("C2PA_ZK_HIDDEN_KEYS").map(PathBuf::from).unwrap_or_else(|| zk_root().join("target/gnark-keys-hidden"));
    let gnark = zk_root().join("target/c2pa-zk-gnark");
    assert!(keys.join("keys.json").exists() && gnark.exists(), "run c2pa-zk-gnark setup --statement hidden-issuer --keys {} first", keys.display());

    let fixture = Fixture::new(true, true);
    let other = Fixture::new(true, true);
    let output = fixture.dir.path().join("anonymized.png");
    Command::cargo_bin("c2pa-x509-zk-anonymizer")
        .unwrap()
        .arg("--third-party").arg("--hide-issuer").arg("fixture-list")
        .arg("--keys").arg(&keys).arg("--gnark").arg(&gnark)
        .arg("--input").arg(fixture.signed()).arg("--output").arg(&output)
        .arg("--trust-list").arg(fixture.pki("trust-list.pem"))
        .assert()
        .success()
        .stdout(predicates::str::contains("hidden among the 2 eligible CAs of fixture-list"));

    let write_policy = |name: &str, list: PathBuf| {
        let path = fixture.dir.path().join(format!("policy-{name}.json"));
        std::fs::write(&path, serde_json::json!({ "snapshots": [{ "name": "fixture-list", "trust_list": list, "from": 0 }] }).to_string()).unwrap();
        path
    };
    let approved = write_policy("approved", fixture.pki("trust-list.pem"));
    let unrelated = write_policy("unrelated", other.pki("trust-list.pem"));
    let verify = |asset: &Path, policy: Option<&Path>| {
        let mut cmd = Command::cargo_bin("c2pa-x509-zk-verify").unwrap();
        cmd.arg("--input").arg(asset)
            .arg("--trust-list").arg(fixture.pki("trust-list.pem"))
            .arg("--tsa-trust-list").arg(fixture.pki("tsa-trust-list.pem"))
            .arg("--keys").arg(&keys).arg("--gnark").arg(&gnark);
        if let Some(policy) = policy {
            cmd.arg("--issuer-policy").arg(policy);
        }
        cmd.assert()
    };
    verify(&output, Some(&approved)).success().stdout(predicates::str::contains("Valid")).stdout(predicates::str::contains("hidden among 2 CAs of fixture-list"));
    verify(&output, None).failure().stderr(predicates::str::contains("needs an issuer policy"));
    verify(&output, Some(&unrelated)).failure().stderr(predicates::str::contains("not that of any snapshot"));

    // Neither CA certificate, nor anything of the signer, is in the output.
    let after = std::fs::read(&output).unwrap();
    let original = fixture.original();
    for (what, needle) in [
        ("issuing CA", std::fs::read(fixture.pki("issuing-ca.der")).unwrap()),
        ("root", std::fs::read(fixture.pki("root.der")).unwrap()),
        ("signer certificate", original.signer_certificate().unwrap().to_vec()),
        ("original signature", original.signature.clone()),
    ] {
        assert!(!after.windows(needle.len()).any(|w| w == needle.as_slice()), "{what} found in the output");
    }

    // A changed claim byte is rejected by the proof.
    let store = manifest_store(&output).unwrap();
    let manifest = active_manifest(&store).unwrap();
    let claim_at = after.windows(manifest.claim.len()).position(|w| w == manifest.claim.as_slice()).unwrap();
    let name_at = claim_at + manifest.claim.windows(8).position(|w| w == b"c2pa-x50").unwrap();
    let mut changed = after.clone();
    changed[name_at] = b'C';
    let tampered = fixture.dir.path().join("hidden-claim-changed.png");
    std::fs::write(&tampered, changed).unwrap();
    verify(&tampered, Some(&approved)).failure().stderr(predicates::str::contains("proof does not verify"));
}

// ---- E8: an anonymized asset as an ingredient ---------------------------------

/// The anonymized asset edited by another signer (its own test PKI and TSA),
/// as an editing or distribution tool would: its pixels resized to half size
/// and saved as a new PNG, signed with the anonymized asset imported as the
/// parent ingredient (`c2pa.opened`, then `c2pa.resized`). Returns the edited
/// asset and a c2pa context trusting both PKIs.
fn edit_as_parent(fixture: &Fixture, anonymized: &Path) -> (PathBuf, impl Fn() -> c2pa::Context) {
    use c2pa_x509_zk_demo::local_tsa::{LocalTsa, TimeStampingSigner};
    let editor = fixture.dir.path().join("editor-pki");
    let ok = std::process::Command::new("bash").arg(zk_root().join("generate-test-pki.sh")).arg("--mirror").arg(&editor).arg("Editor")
        .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success();
    assert!(ok, "generate-test-pki.sh failed");
    let read = |p: PathBuf| std::fs::read_to_string(p).unwrap();
    let chain = format!("{}\n{}", read(editor.join("signer.pem")).trim(), read(editor.join("issuing-ca.pem")).trim());
    let signer = c2pa::create_signer::from_keys(chain.as_bytes(), read(editor.join("signer.key")).as_bytes(), c2pa::SigningAlg::Es256, None).unwrap();
    let signer = TimeStampingSigner::new(signer, LocalTsa { cert: editor.join("tsa.pem"), key: editor.join("tsa.key") });

    let anchors = ["trust-list.pem", "tsa-trust-list.pem"].iter()
        .flat_map(|f| [read(fixture.pki(f)), read(editor.join(f))])
        .collect::<Vec<_>>()
        .join("\n");
    let ekus = [C2PA_CLAIM_SIGNING_EKU, EMAIL_PROTECTION_EKU, TIME_STAMPING_EKU].join("\n");
    let settings = serde_json::json!({
        "trust": { "trust_anchors": anchors, "trust_config": ekus },
        "verify": { "verify_trust": true, "verify_timestamp_trust": true },
    });
    let context = move || c2pa::Context::new().with_settings(settings.clone()).unwrap();

    let definition = serde_json::json!({
        "claim_version": 2,
        "claim_generator_info": [{ "name": "e8-test-editor", "version": "0.1" }],
        "assertions": [{ "label": "c2pa.actions.v2", "data": { "actions": [
            { "action": "c2pa.opened", "parameters": { "ingredientIds": ["parent"] } },
            { "action": "c2pa.resized" }
        ] } }]
    });
    let mut builder = c2pa::Builder::from_context(context()).with_definition(definition.to_string()).unwrap();
    builder
        .add_ingredient_from_stream(
            serde_json::json!({ "title": "anonymized.png", "relationship": "parentOf", "label": "parent" }).to_string(),
            "image/png",
            &mut std::fs::File::open(anonymized).unwrap(),
        )
        .unwrap();
    // The derived image: the anonymized pixels at half size, a new PNG with
    // no manifest of its own until the editor signs it.
    let pixels = image::open(anonymized).unwrap();
    let resized = pixels.resize_exact(pixels.width() / 2, pixels.height() / 2, image::imageops::FilterType::Triangle);
    let mut derived = std::io::Cursor::new(Vec::new());
    resized.write_to(&mut derived, image::ImageFormat::Png).unwrap();
    derived.set_position(0);
    let edited = fixture.dir.path().join("edited.png");
    builder.sign(&signer, "image/png", &mut derived, &mut std::fs::File::create(&edited).unwrap()).unwrap();
    let (before, after) = (image::image_dimensions(anonymized).unwrap(), image::image_dimensions(&edited).unwrap());
    assert_eq!(after, (before.0 / 2, before.1 / 2), "the edited asset is the resized image");
    (edited, context)
}

/// The edited asset with its provenance link to the ingredient broken: one
/// letter changed in the ingredient's actions assertion ("Created by" becomes
/// "created by"). That assertion is covered by the ingredient's own claim and
/// by the editor's ingredient hash, but not by the ZK proof, which covers the
/// ingredient's claim. The store is rewritten with c2pa so the PNG stays
/// well-formed.
fn with_broken_ingredient_link(fixture: &Fixture, edited: &Path) -> PathBuf {
    let store = manifest_store(edited).unwrap();
    let text = b"Created by the c2pa-x509-zk test signer.";
    let positions: Vec<_> = store.windows(text.len()).enumerate().filter(|(_, w)| *w == text).map(|(i, _)| i).collect();
    assert_eq!(positions.len(), 1, "the description appears once, in the ingredient's manifest");
    let mut changed = store.clone();
    changed[positions[0]] = b'c';
    let asset = std::fs::read(edited).unwrap();
    let written = c2pa::jumbf_io::save_jumbf_to_memory("png", &asset, &changed).unwrap();
    let broken = fixture.dir.path().join("broken-link.png");
    std::fs::write(&broken, written).unwrap();
    broken
}

/// E8, "anonymize first, then edit": c2pa-rs keeps an anonymized asset as an
/// ingredient. The ZK-signed manifest is carried unchanged, without the
/// original signer's certificate; the editor's ingredient hashes resolve to
/// it; and its ZK signature is reported as unsupported, not trusted. (The
/// proof itself is checked with real keys below.)
#[test]
fn anonymized_asset_is_kept_as_an_ingredient() {
    let fixture = Fixture::new(true, true);
    let anonymized = replaced_with_placeholder(&fixture);
    let (edited, context) = edit_as_parent(&fixture, &anonymized);

    // The ZK-signed manifest is carried byte for byte.
    let zk = active_manifest(&manifest_store(&anonymized).unwrap()).unwrap();
    let store = manifest_store(&edited).unwrap();
    let all = c2pa_x509_zk_demo::jumbf::manifests(&store).unwrap();
    assert_eq!(all.len(), 2);
    let ingredient = all.iter().find(|m| m.label == zk.label).expect("the anonymized manifest in the edited asset");
    assert_eq!((&ingredient.claim, &ingredient.cose_sign1), (&zk.claim, &zk.cose_sign1));
    assert_ne!(all.last().unwrap().label, zk.label, "the editor's manifest is the active one");

    // Nothing of the original signer is restored.
    let original = fixture.original();
    let signer = x509_cert::Certificate::from_der(original.signer_certificate().unwrap()).unwrap();
    let after = std::fs::read(&edited).unwrap();
    for (what, needle) in [
        ("signer certificate", original.signer_certificate().unwrap()),
        ("signer key", signer.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes()),
        ("original signature", original.signature.as_slice()),
    ] {
        assert!(!after.windows(needle.len()).any(|w| w == needle), "{what} found in the edited asset");
    }

    // c2pa: the editor's manifest is valid and trusted, its ingredient hash
    // resolves, and the only failures are the ingredient's ZK signature.
    let reader = c2pa::Reader::from_context(context()).with_stream("image/png", std::fs::File::open(&edited).unwrap()).unwrap();
    let results = reader.validation_results().unwrap();
    let active = results.active_manifest().unwrap();
    assert!(active.failure().is_empty(), "{:?}", active.failure());
    let active_codes: Vec<_> = active.success().iter().map(|s| s.code()).collect();
    for code in ["claimSignature.validated", "signingCredential.trusted", "timeStamp.trusted"] {
        assert!(active_codes.contains(&code), "{code} missing: {active_codes:?}");
    }
    let deltas = results.ingredient_deltas().unwrap();
    assert_eq!(deltas.len(), 1);
    let delta = serde_json::to_value(&deltas[0]).unwrap();
    let codes = |kind: &str| -> Vec<String> {
        delta["validationDeltas"][kind].as_array().unwrap().iter().map(|s| s["code"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(codes("success"), ["ingredient.manifest.validated"]);
    assert_eq!(codes("failure"), ["algorithm.unsupported", "claimSignature.mismatch"]);
    let mut status: Vec<_> = reader.validation_status().unwrap().iter().map(|s| s.code().to_string()).collect();
    status.sort();
    assert_eq!(status, ["algorithm.unsupported", "claimSignature.mismatch"]);
    assert_eq!(reader.validation_state(), c2pa::ValidationState::Invalid, "the unsupported ingredient signature makes the asset invalid to c2pa");
}

/// E8 with real proofs: the anonymized asset's proof still verifies as an
/// ingredient of the edited asset, a changed ingredient claim is rejected, and
/// a broken provenance link does not affect it (that is standard validation's
/// to report).
/// Needs keys and the gnark CLI as for the end-to-end test.
#[test]
#[ignore = "needs gnark keys and CLI; proves for ~1.5 min"]
fn anonymized_ingredient_proof_verifies_after_an_edit() {
    let keys = std::env::var_os("C2PA_ZK_KEYS").map(PathBuf::from).unwrap_or_else(|| zk_root().join("target/gnark-keys"));
    let gnark = zk_root().join("target/c2pa-zk-gnark");
    assert!(keys.join("keys.json").exists() && gnark.exists(), "run c2pa-zk-gnark setup --keys {} first", keys.display());

    let fixture = Fixture::new(true, true);
    let anonymized = fixture.dir.path().join("anonymized.png");
    Command::cargo_bin("c2pa-x509-zk-anonymizer")
        .unwrap()
        .arg("--third-party").arg("--keys").arg(&keys).arg("--gnark").arg(&gnark)
        .arg("--input").arg(fixture.signed()).arg("--output").arg(&anonymized)
        .arg("--trust-list").arg(fixture.pki("trust-list.pem"))
        .assert()
        .success();
    let (edited, _) = edit_as_parent(&fixture, &anonymized);

    let label = active_manifest(&manifest_store(&anonymized).unwrap()).unwrap().label;
    let trust = c2pa_x509_zk_demo::TrustList::from_file(&fixture.pki("trust-list.pem")).unwrap();
    let tsa_trust = fixture.pki("tsa-trust-list.pem");
    let prover = Prover { cli: gnark, keys };
    let store = manifest_store(&edited).unwrap();
    let report = third_party::verify_ingredient(&store, &label, &trust, &tsa_trust, &prover).unwrap();
    let issuer = c2pa_x509_zk_demo::extract_subject_dn(&std::fs::read(fixture.pki("issuing-ca.der")).unwrap()).unwrap();
    assert_eq!(report.issuer, issuer);

    // A changed byte in the ingredient's claim (the claim generator's name):
    // the proof is bound to the claim.
    let ingredient = c2pa_x509_zk_demo::jumbf::manifests(&store).unwrap().into_iter().find(|m| m.label == label).unwrap();
    let mut changed = store.clone();
    let claim_at = changed.windows(ingredient.claim.len()).position(|w| w == ingredient.claim.as_slice()).unwrap();
    let name_at = claim_at + ingredient.claim.windows(8).position(|w| w == b"c2pa-x50").unwrap();
    changed[name_at] = b'C';
    let err = third_party::verify_ingredient(&changed, &label, &trust, &tsa_trust, &prover).unwrap_err().to_string();
    assert!(err.contains("proof does not verify"), "{err}");

    // Negative control: with the editor's link to the ingredient broken (see
    // broken_ingredient_link_is_reported_by_c2pa), the ingredient's proof still
    // verifies. verify_ingredient establishes the ingredient's signature, not
    // the provenance chain; that needs standard validation as well.
    let broken = with_broken_ingredient_link(&fixture, &edited);
    third_party::verify_ingredient(&manifest_store(&broken).unwrap(), &label, &trust, &tsa_trust, &prover).unwrap();

    // The active manifest is not an anonymized one: verify_ingredient refuses it.
    let editor_label = c2pa_x509_zk_demo::jumbf::manifests(&store).unwrap().last().unwrap().label.clone();
    assert!(third_party::verify_ingredient(&store, &editor_label, &trust, &tsa_trust, &prover).is_err());
}

/// E8 negative control: a broken link from the editor to the ingredient is
/// reported by standard validation (the ingredient's hash no longer matches),
/// whatever the ingredient's proof says; the proof is checked below.
#[test]
fn broken_ingredient_link_is_reported_by_c2pa() {
    let fixture = Fixture::new(true, true);
    let anonymized = replaced_with_placeholder(&fixture);
    let (edited, context) = edit_as_parent(&fixture, &anonymized);
    let broken = with_broken_ingredient_link(&fixture, &edited);
    let reader = c2pa::Reader::from_context(context()).with_stream("image/png", std::fs::File::open(&broken).unwrap()).unwrap();
    let results = reader.validation_results().unwrap();
    assert!(results.active_manifest().unwrap().failure().is_empty(), "the editor's own manifest is untouched");
    let delta = serde_json::to_value(&results.ingredient_deltas().unwrap()[0]).unwrap();
    let codes = |kind: &str| -> Vec<String> {
        delta["validationDeltas"][kind].as_array().unwrap().iter().map(|s| s["code"].as_str().unwrap().to_string()).collect()
    };
    assert!(codes("success").is_empty(), "{:?}", codes("success"));
    let failures = codes("failure");
    for code in ["ingredient.manifest.mismatch", "assertion.hashedURI.mismatch"] {
        assert!(failures.contains(&code.to_string()), "{code} missing: {failures:?}");
    }
    // The overall state is Invalid with or without the broken link: only the
    // codes tell them apart.
    assert_eq!(reader.validation_state(), c2pa::ValidationState::Invalid);
}
