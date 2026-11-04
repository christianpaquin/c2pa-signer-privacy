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
