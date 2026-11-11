//! Trust lists and issuing-chain validation.
//!
//! An anonymized asset's `x5chain` carries the issuing CA chain (issuing CA
//! first, never the signer's certificate). The verifier validates that chain
//! against a trust list, then checks the issuing CA's key against the proof's
//! public inputs. The circuit proves the rest: that the issuing CA signed a
//! certificate for the key that signed the asset.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::path::Path;
use x509_cert::Certificate;

/// ServiceStatus of an entry in the C2PA trust list JSON that is trusted.
const LOTE_TRUSTED_STATUS: &str = "http://c2pa.org/conformance/trust-list/trusted";

/// A set of trust anchors (DER certificates).
#[derive(Debug, Clone, Default)]
pub struct TrustList {
    pub anchors: Vec<Vec<u8>>,
    /// Entries in a JSON trust list that were not loaded because their
    /// ServiceStatus is not "trusted".
    pub skipped: usize,
}

impl TrustList {
    /// Load a trust list: the C2PA JSON format if the file ends in `.json`,
    /// otherwise a PEM bundle (or a single DER certificate).
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("failed to read trust list {path:?}"))?;
        let list = if path.extension().is_some_and(|e| e == "json") {
            Self::from_lote_json(std::str::from_utf8(&bytes)?)?
        } else if bytes.starts_with(b"-----") || bytes.windows(11).any(|w| w == b"-----BEGIN ") {
            Self { anchors: pem_to_der_certs(std::str::from_utf8(&bytes)?)?, skipped: 0 }
        } else {
            Self { anchors: vec![bytes], skipped: 0 }
        };
        if list.anchors.is_empty() {
            bail!("trust list {path:?} contains no certificates");
        }
        for anchor in &list.anchors {
            Certificate::from_der(anchor).map_err(|e| anyhow!("invalid certificate in trust list: {e}"))?;
        }
        Ok(list)
    }

    /// Parse the C2PA trust list JSON ("List of Trusted Entities"). Only
    /// services whose ServiceStatus is "trusted" are loaded.
    pub fn from_lote_json(json: &str) -> Result<Self> {
        let root: serde_json::Value = serde_json::from_str(json)?;
        let entities = root["LoTE"]["TrustedEntitiesList"]
            .as_array()
            .ok_or_else(|| anyhow!("not a C2PA trust list: missing LoTE.TrustedEntitiesList"))?;
        let mut list = Self::default();
        for entity in entities {
            for service in entity["TrustedEntityServices"].as_array().into_iter().flatten() {
                let info = &service["ServiceInformation"];
                let certs = info["ServiceDigitalIdentity"]["X509Certificates"].as_array();
                let count = certs.map_or(0, Vec::len);
                if info["ServiceStatus"].as_str() != Some(LOTE_TRUSTED_STATUS) {
                    list.skipped += count;
                    continue;
                }
                for cert in certs.into_iter().flatten() {
                    let b64 = cert["val"].as_str().ok_or_else(|| anyhow!("trust list certificate without \"val\""))?;
                    list.anchors.push(base64::engine::general_purpose::STANDARD.decode(b64)?);
                }
            }
        }
        Ok(list)
    }

    pub fn is_anchor(&self, cert_der: &[u8]) -> bool {
        self.anchors.iter().any(|a| a == cert_der)
    }
}

/// Decode every certificate in a PEM bundle.
pub fn pem_to_der_certs(pem: &str) -> Result<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after.find(END).ok_or_else(|| anyhow!("malformed PEM: missing end marker"))?;
        let b64: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
        certs.push(base64::engine::general_purpose::STANDARD.decode(b64)?);
        rest = &after[end + END.len()..];
    }
    Ok(certs)
}

/// Stable identifier for a CA key: hex SHA-256 of its SubjectPublicKeyInfo.
/// Unlike a hash of the whole certificate, it survives certificate renewal.
pub fn spki_key_id(cert_der: &[u8]) -> Result<String> {
    let cert = Certificate::from_der(cert_der).map_err(|e| anyhow!("failed to parse certificate: {e}"))?;
    let spki = cert.tbs_certificate.subject_public_key_info.to_der()?;
    Ok(hex::encode(Sha256::digest(spki)))
}

/// Validate an issuing chain (issuing CA first, then any further
/// intermediates) against a trust list at Unix time `at`, and return the
/// validated path: the chain up to and including the first certificate that
/// is a trust anchor, or the whole chain when its last certificate is issued
/// by an anchor. Anything after that point is not part of the path and must
/// not be embedded or relied on.
///
/// Each certificate must be a CA, valid at `at`, allowed to sign certificates,
/// free of unrecognized critical extensions, and within its path-length
/// constraint. The hidden signer sits below the first issuing CA, so the
/// certificate at position `k` has `k` CA certificates below it and needs
/// `pathLen >= k`; an anchor that issued the last certificate needs
/// `pathLen >= chain.len()`. Self-issued certificates get no special
/// treatment (stricter than RFC 5280).
pub fn validate_issuing_chain(chain: &[Vec<u8>], trust: &TrustList, at: u64) -> Result<Vec<Vec<u8>>> {
    if chain.is_empty() {
        bail!("issuing chain is empty");
    }
    for (i, der) in chain.iter().enumerate() {
        let cert = parse(der)?;
        check_ca(&cert, Some(at), i).with_context(|| format!("issuing chain certificate {i}"))?;
        if trust.is_anchor(der) {
            return Ok(chain[..=i].to_vec());
        }
        match chain.get(i + 1) {
            Some(next) => verify_issued_by(der, next)
                .with_context(|| format!("issuing chain certificate {i} is not issued by certificate {}", i + 1))?,
            None => {
                // Several anchors can verify the signature (for example an
                // expired and a renewed certificate for the same key); the
                // path is valid if any of them is a valid anchor for it.
                let mut last_err = None;
                for anchor in trust.anchors.iter().filter(|a| verify_issued_by(der, a).is_ok()) {
                    match check_ca(&parse(anchor)?, Some(at), chain.len()) {
                        Ok(()) => return Ok(chain.to_vec()),
                        Err(e) => last_err = Some(e.context("trust anchor")),
                    }
                }
                return Err(last_err.unwrap_or_else(|| anyhow!("issuing chain does not chain to the trust list")));
            }
        }
    }
    unreachable!("loop returns on the last certificate")
}

/// Find and validate the issuing path for `leaf` at Unix time `at`: the
/// signed asset's intermediates if their first certificate issued `leaf`,
/// otherwise a trust anchor that did. Every candidate is tried until one
/// yields a fully valid path (see `validate_issuing_chain`), so the result
/// does not depend on the order of the trust list.
pub fn issuing_path_for(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    trust: &TrustList,
    at: u64,
) -> Result<Vec<Vec<u8>>> {
    let mut candidates: Vec<Vec<Vec<u8>>> = Vec::new();
    if intermediates.first().is_some_and(|first| verify_issued_by(leaf_der, first).is_ok()) {
        candidates.push(intermediates.to_vec());
    }
    for anchor in trust.anchors.iter().filter(|a| verify_issued_by(leaf_der, a).is_ok()) {
        candidates.push(vec![anchor.clone()]);
    }

    let mut last_err = None;
    for candidate in &candidates {
        match validate_issuing_chain(candidate, trust, at) {
            Ok(path) => return Ok(path),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no certificate in the chain or trust list issued the signer certificate")))
}

/// Verify that `issuer_der` issued `child_der`: names match and the issuer's
/// key verifies the child's signature over its original TBS bytes.
pub fn verify_issued_by(child_der: &[u8], issuer_der: &[u8]) -> Result<()> {
    let child = parse(child_der)?;
    let issuer = parse(issuer_der)?;
    if child.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        bail!("issuer name does not match");
    }
    let tbs = tbs_bytes(child_der)?;
    let sig = child.signature.as_bytes().ok_or_else(|| anyhow!("signature is not byte-aligned"))?;
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let key = spki.subject_public_key.as_bytes().ok_or_else(|| anyhow!("issuer key is not byte-aligned"))?;

    match child.signature_algorithm.oid.to_string().as_str() {
        "1.2.840.10045.4.3.2" => verify_ecdsa(spki, key, &Sha256::digest(tbs), sig),
        "1.2.840.10045.4.3.3" => verify_ecdsa(spki, key, &Sha384::digest(tbs), sig),
        "1.2.840.113549.1.1.11" => verify_rsa::<Sha256>(key, tbs, sig),
        "1.2.840.113549.1.1.12" => verify_rsa::<Sha384>(key, tbs, sig),
        "1.2.840.113549.1.1.13" => verify_rsa::<Sha512>(key, tbs, sig),
        other => bail!("unsupported certificate signature algorithm {other}"),
    }
}

fn verify_ecdsa(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned, key: &[u8], prehash: &[u8], sig: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
        .map(|oid| oid.to_string());
    match curve.as_deref() {
        Some("1.2.840.10045.3.1.7") => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key)?;
            vk.verify_prehash(prehash, &p256::ecdsa::Signature::from_der(sig)?)?;
        }
        Some("1.3.132.0.34") => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key)?;
            vk.verify_prehash(prehash, &p384::ecdsa::Signature::from_der(sig)?)?;
        }
        other => bail!("unsupported issuer EC curve {other:?}"),
    }
    Ok(())
}

fn verify_rsa<D>(key: &[u8], tbs: &[u8], sig: &[u8]) -> Result<()>
where
    D: Digest + const_oid::AssociatedOid,
{
    use rsa::pkcs1::DecodeRsaPublicKey;
    let pk = rsa::RsaPublicKey::from_pkcs1_der(key)?;
    pk.verify(rsa::Pkcs1v15Sign::new::<D>(), &D::digest(tbs), sig)?;
    Ok(())
}

fn parse(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|e| anyhow!("failed to parse certificate: {e}"))
}

/// EKUs that let a CA issue C2PA claim-signing certificates: anyExtendedKeyUsage,
/// C2PA claim signing, document signing, email protection, and Microsoft's
/// C2PA signing OID (the purposes real signer certificates use; see
/// DEPLOYMENT-FINDINGS.md).
const CLAIM_SIGNING_CA_EKUS: [&str; 5] = [
    "2.5.29.37.0",
    "1.3.6.1.4.1.62558.2.1",
    "1.3.6.1.5.5.7.3.36",
    "1.3.6.1.5.5.7.3.4",
    "1.3.6.1.4.1.311.76.59.1.9",
];

/// The certificate must be a CA that can sign certificates, valid at `at`,
/// with no unrecognized critical extension, an EKU (if any) that allows C2PA
/// claim signing, and a path-length constraint (if any) allowing `cas_below`
/// CA certificates between it and the signer.
fn check_ca(cert: &Certificate, at: Option<u64>, cas_below: usize) -> Result<()> {
    use const_oid::db::rfc5280::{
        ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE,
        ID_CE_SUBJECT_KEY_IDENTIFIER,
    };
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

    let tbs = &cert.tbs_certificate;
    let extensions = tbs.extensions.as_deref().unwrap_or_default();
    let find = |oid| extensions.iter().find(|e| e.extn_id == oid);

    let basic = find(ID_CE_BASIC_CONSTRAINTS)
        .map(|e| BasicConstraints::from_der(e.extn_value.as_bytes()))
        .transpose()
        .map_err(|e| anyhow!("invalid basicConstraints: {e}"))?;
    let Some(basic) = basic.filter(|bc| bc.ca) else {
        bail!("{} is not a CA certificate", tbs.subject);
    };
    if let Some(path_len) = basic.path_len_constraint {
        if (path_len as usize) < cas_below {
            bail!(
                "{}: path length constraint exceeded (pathLen {path_len}, {cas_below} CA certificate(s) below it)",
                tbs.subject
            );
        }
    }

    if let Some(ext) = find(ID_CE_KEY_USAGE) {
        let usage = KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| anyhow!("invalid keyUsage: {e}"))?;
        if !usage.key_cert_sign() {
            bail!("{}: keyUsage does not allow certificate signing", tbs.subject);
        }
    }

    // An EKU on a CA restricts the purposes it may issue for (CA/Browser
    // Forum and common practice; RFC 5280 does not define it for CAs). It
    // must decode, and allow claim signing: anyExtendedKeyUsage, or one of the
    // EKUs real C2PA signer certificates carry.
    if let Some(ext) = find(ID_CE_EXT_KEY_USAGE) {
        let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
            .map_err(|e| anyhow!("{}: invalid extendedKeyUsage: {e}", tbs.subject))?;
        if !eku.0.iter().any(|oid| CLAIM_SIGNING_CA_EKUS.contains(&oid.to_string().as_str())) {
            bail!("{}: extendedKeyUsage does not allow C2PA claim signing", tbs.subject);
        }
    }

    // Critical extensions this validator does not process (for example name
    // constraints or policy constraints) must cause rejection (RFC 5280 4.2).
    let understood = [
        ID_CE_BASIC_CONSTRAINTS,
        ID_CE_KEY_USAGE,
        ID_CE_EXT_KEY_USAGE,
        ID_CE_SUBJECT_KEY_IDENTIFIER,
        ID_CE_AUTHORITY_KEY_IDENTIFIER,
    ];
    if let Some(ext) = extensions.iter().find(|e| e.critical && !understood.contains(&e.extn_id)) {
        bail!("{}: unsupported critical extension {}", tbs.subject, ext.extn_id);
    }

    let Some(at) = at else { return Ok(()) };
    let not_before = tbs.validity.not_before.to_unix_duration().as_secs();
    let not_after = tbs.validity.not_after.to_unix_duration().as_secs();
    if at < not_before || at > not_after {
        bail!("{} is not valid at the verification time", tbs.subject);
    }
    Ok(())
}

/// The trust list's certificates eligible as hidden issuers (roadmap H4,
/// HIDING-THE-ISSUER.md, I1), and the reasons the others are not: the CA
/// check applied to an issuing CA (`check_ca`) except validity, which the
/// hidden-issuer statement checks at the attested time, in the circuit; and
/// no name constraints or policy constraints, critical or not, which
/// constrain the signer's subject, hidden from the verifier. The key type is
/// filtered by the tree builder (P-384 for the current statement).
pub fn eligible_issuers(trust: &TrustList) -> (Vec<Vec<u8>>, Vec<String>) {
    use const_oid::db::rfc5280::{ID_CE_NAME_CONSTRAINTS, ID_CE_POLICY_CONSTRAINTS};
    let (mut eligible, mut excluded) = (Vec::new(), Vec::new());
    for der in &trust.anchors {
        let checked = parse(der).and_then(|cert| {
            check_ca(&cert, None, 0)?;
            let subject_constraint = cert.tbs_certificate.extensions.as_deref().unwrap_or_default().iter()
                .find(|e| e.extn_id == ID_CE_NAME_CONSTRAINTS || e.extn_id == ID_CE_POLICY_CONSTRAINTS);
            if let Some(ext) = subject_constraint {
                bail!("{}: carries {} (name or policy constraints cannot be checked against a hidden subject)", cert.tbs_certificate.subject, ext.extn_id);
            }
            Ok(())
        });
        match checked {
            Ok(()) => eligible.push(der.clone()),
            Err(e) => excluded.push(e.to_string()),
        }
    }
    (eligible, excluded)
}

/// The original DER bytes of the TBSCertificate (the first element of the
/// outer SEQUENCE). Signatures are verified over these bytes rather than a
/// re-encoding, which could differ for non-canonical certificates.
fn tbs_bytes(cert_der: &[u8]) -> Result<&[u8]> {
    fn header(bytes: &[u8]) -> Result<(usize, usize)> {
        // Returns (header length, content length) for a DER TLV starting at bytes[0].
        if bytes.len() < 2 || bytes[0] != 0x30 {
            bail!("expected a DER SEQUENCE");
        }
        let first = bytes[1] as usize;
        if first < 0x80 {
            return Ok((2, first));
        }
        let n = first & 0x7f;
        if n == 0 || n > 4 || bytes.len() < 2 + n {
            bail!("unsupported DER length");
        }
        let len = bytes[2..2 + n].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        Ok((2 + n, len))
    }
    let (outer_hdr, _) = header(cert_der)?;
    let inner = &cert_der[outer_hdr..];
    let (tbs_hdr, tbs_len) = header(inner)?;
    inner
        .get(..tbs_hdr + tbs_len)
        .ok_or_else(|| anyhow!("truncated TBSCertificate"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pki::TestPki;

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn pem_and_json_trust_lists_load_the_same_anchors() {
        let pki = TestPki::generate("Trust Test");
        let pem = TrustList::from_file(&pki.file("trust-list.pem")).unwrap();
        let json = TrustList::from_file(&pki.file("trust-list.json")).unwrap();
        assert_eq!(pem.anchors.len(), 2);
        assert_eq!(pem.anchors, json.anchors);
        assert_eq!(json.skipped, 0);
    }

    #[test]
    fn json_trust_list_skips_services_not_marked_trusted() {
        let pki = TestPki::generate("Trust Test");
        let json = std::fs::read_to_string(pki.file("trust-list.json")).unwrap();
        let edited = json.replacen(LOTE_TRUSTED_STATUS, "", 1);
        let list = TrustList::from_lote_json(&edited).unwrap();
        assert_eq!(list.anchors.len(), 1);
        assert_eq!(list.skipped, 1);
    }

    #[test]
    fn issuing_ca_that_is_an_anchor_validates() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("trust-list.pem")).unwrap();
        validate_issuing_chain(&[pki.read("issuing-ca.der")], &trust, now()).unwrap();
    }

    #[test]
    fn issuing_ca_chaining_to_a_root_anchor_validates() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("root.pem")).unwrap();
        validate_issuing_chain(&[pki.read("issuing-ca.der")], &trust, now()).unwrap();
    }

    #[test]
    fn chain_from_another_pki_is_rejected() {
        let pki = TestPki::generate("Trust Test");
        let other = TestPki::generate("Other PKI");
        let trust = TrustList::from_file(&pki.file("trust-list.pem")).unwrap();
        let err = validate_issuing_chain(&[other.read("issuing-ca.der")], &trust, now()).unwrap_err();
        assert!(err.to_string().contains("does not chain"), "{err}");
    }

    #[test]
    fn chain_with_wrong_link_is_rejected() {
        let pki = TestPki::generate("Trust Test");
        let other = TestPki::generate("Other PKI");
        let trust = TrustList::from_file(&pki.file("root.pem")).unwrap();
        // Our issuing CA followed by another PKI's root: the link does not verify.
        let chain = [pki.read("issuing-ca.der"), other.read("root.der")];
        assert!(validate_issuing_chain(&chain, &trust, now()).is_err());
    }

    #[test]
    fn signer_certificate_is_not_accepted_as_issuing_ca() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("trust-list.pem")).unwrap();
        let err = validate_issuing_chain(&[pki.read("signer.der")], &trust, now()).unwrap_err();
        assert!(format!("{err:#}").contains("not a CA"), "{err:#}");
    }

    #[test]
    fn expired_issuing_ca_is_rejected() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("trust-list.pem")).unwrap();
        let far_future = now() + 20 * 365 * 24 * 3600;
        assert!(validate_issuing_chain(&[pki.read("issuing-ca.der")], &trust, far_future).is_err());
    }

    /// Issue an extra CA certificate inside the test PKI with openssl: a new
    /// key, signed by `issuer` ("root" or "issuing-ca"), with the given
    /// extension lines. Returns its DER.
    fn issue_ca(pki: &TestPki, name: &str, issuer: &str, extensions: &str) -> Vec<u8> {
        let dir = &pki.path;
        let run = |args: &[&str]| {
            let ok = std::process::Command::new("openssl").args(args).current_dir(dir)
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .status().unwrap().success();
            assert!(ok, "openssl {args:?} failed");
        };
        let (key, csr, ext, der) =
            (format!("{name}.key"), format!("{name}.csr"), format!("{name}.ext"), format!("{name}.der"));
        run(&["ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", &key]);
        run(&["req", "-new", "-key", &key, "-subj", &format!("/C=US/O=Extra/CN={name}"), "-out", &csr]);
        std::fs::write(dir.join(&ext), extensions).unwrap();
        run(&["x509", "-req", "-in", &csr, "-CA", &format!("{issuer}.pem"), "-CAkey", &format!("{issuer}.key"),
              "-CAcreateserial", "-sha256", "-days", "30", "-extfile", &ext, "-outform", "DER", "-out", &der]);
        pki.read(&der)
    }

    /// H4 eligibility: the CA check without validity, and no name or policy
    /// constraints, critical or not.
    #[test]
    fn eligible_issuers_apply_the_ca_check_and_exclude_subject_constraints() {
        let pki = TestPki::generate("Trust Test");
        let ca = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n";
        let plain = issue_ca(&pki, "plain-ca", "root", ca);
        let not_ca = issue_ca(&pki, "not-a-ca", "root", "basicConstraints=critical,CA:FALSE\n");
        let no_cert_sign = issue_ca(&pki, "no-cert-sign", "root", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n");
        let names = issue_ca(&pki, "name-constrained", "root", &format!("{ca}nameConstraints=permitted;DNS:example.com\n"));
        let names_critical = issue_ca(&pki, "name-constrained-critical", "root", &format!("{ca}nameConstraints=critical,permitted;DNS:example.com\n"));
        let policy = issue_ca(&pki, "policy-constrained", "root", &format!("{ca}policyConstraints=requireExplicitPolicy:0\n"));
        let trust = TrustList {
            anchors: vec![plain.clone(), not_ca, no_cert_sign, names, names_critical, policy, pki.read("issuing-ca.der")],
            skipped: 0,
        };
        let (eligible, excluded) = eligible_issuers(&trust);
        assert_eq!(eligible, vec![plain, pki.read("issuing-ca.der")], "excluded: {excluded:?}");
        assert_eq!(excluded.len(), 5, "{excluded:?}");
        // Non-critical name and policy constraints are excluded by the new
        // rule; critical name constraints already by the CA check.
        assert_eq!(excluded.iter().filter(|e| e.contains("name or policy constraints")).count(), 2, "{excluded:?}");
        assert!(excluded.iter().any(|e| e.contains("name-constrained-critical") && e.contains("unsupported critical extension")), "{excluded:?}");
    }

    #[test]
    fn validated_path_stops_at_the_anchor() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("trust-list.pem")).unwrap();
        // The issuing CA is an anchor, so anything after it (here the signer
        // certificate) is not part of the path and must not be returned.
        let chain = [pki.read("issuing-ca.der"), pki.read("signer.der")];
        assert_eq!(validate_issuing_chain(&chain, &trust, now()).unwrap(), vec![pki.read("issuing-ca.der")]);
    }

    #[test]
    fn path_length_constraint_is_enforced_below_a_root_anchor() {
        let pki = TestPki::generate("Trust Test");
        // root -> issuing CA (pathlen:0) -> subordinate CA -> (signer)
        let sub = issue_ca(&pki, "sub-ca", "issuing-ca", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n");
        let trust = TrustList::from_file(&pki.file("root.pem")).unwrap();
        let err = validate_issuing_chain(&[sub, pki.read("issuing-ca.der")], &trust, now()).unwrap_err();
        assert!(format!("{err:#}").contains("path length constraint exceeded"), "{err:#}");
    }

    #[test]
    fn path_length_constraint_of_the_anchor_is_enforced() {
        let pki = TestPki::generate("Trust Test");
        // The pathlen:0 issuing CA is the anchor, and it issued another CA.
        let sub = issue_ca(&pki, "sub-ca", "issuing-ca", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n");
        let trust = TrustList::from_file(&pki.file("issuing-ca.pem")).unwrap();
        let err = validate_issuing_chain(&[sub], &trust, now()).unwrap_err();
        assert!(format!("{err:#}").contains("path length constraint exceeded"), "{err:#}");
    }

    #[test]
    fn ca_without_certificate_signing_key_usage_is_rejected() {
        let pki = TestPki::generate("Trust Test");
        let ca = issue_ca(&pki, "no-certsign", "root", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,digitalSignature\n");
        let trust = TrustList::from_file(&pki.file("root.pem")).unwrap();
        let err = validate_issuing_chain(&[ca], &trust, now()).unwrap_err();
        assert!(format!("{err:#}").contains("does not allow certificate signing"), "{err:#}");
    }

    #[test]
    fn ca_with_unknown_critical_extension_is_rejected() {
        let pki = TestPki::generate("Trust Test");
        let ca = issue_ca(&pki, "crit-ext", "root",
            "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\n1.3.6.1.4.1.55555.1=critical,DER:05:00\n");
        let trust = TrustList::from_file(&pki.file("root.pem")).unwrap();
        let err = validate_issuing_chain(&[ca], &trust, now()).unwrap_err();
        assert!(format!("{err:#}").contains("unsupported critical extension"), "{err:#}");
    }

    #[test]
    fn issuing_path_for_signer_uses_provided_intermediates_then_anchors() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("trust-list.pem")).unwrap();
        let signer = pki.read("signer.der");
        let ica = pki.read("issuing-ca.der");
        assert_eq!(issuing_path_for(&signer, &[ica.clone()], &trust, now()).unwrap(), vec![ica.clone()]);
        // Not in the signed chain: found in the trust list instead.
        assert_eq!(issuing_path_for(&signer, &[], &trust, now()).unwrap(), vec![ica]);
    }

    /// Re-issue an existing certificate (`name`.pem/.key) for the same subject
    /// and key, valid for one day only, signed by `issuer` ("self" for a root).
    fn reissue_short_lived(pki: &TestPki, name: &str, issuer: &str, extensions: &str) -> Vec<u8> {
        let dir = &pki.path;
        let run = |args: &[&str]| {
            let ok = std::process::Command::new("openssl").args(args).current_dir(dir)
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .status().unwrap().success();
            assert!(ok, "openssl {args:?} failed");
        };
        let (csr, ext, der) = (format!("{name}-short.csr"), format!("{name}-short.ext"), format!("{name}-short.der"));
        run(&["x509", "-x509toreq", "-in", &format!("{name}.pem"), "-signkey", &format!("{name}.key"), "-out", &csr]);
        std::fs::write(dir.join(&ext), extensions).unwrap();
        let mut args = vec!["x509", "-req", "-in", &csr, "-days", "1", "-sha256", "-extfile", &ext, "-outform", "DER", "-out", &der];
        let (ca, ca_key) = (format!("{issuer}.pem"), format!("{issuer}.key"));
        let own_key = format!("{name}.key");
        if issuer == "self" {
            args.extend(["-signkey", own_key.as_str()]);
        } else {
            args.extend(["-CA", ca.as_str(), "-CAkey", ca_key.as_str(), "-CAcreateserial"]);
        }
        run(&args);
        pki.read(&der)
    }

    fn two_days_from_now() -> u64 {
        now() + 2 * 24 * 3600
    }

    /// Regression test (PR #14 re-review): an expired and a valid anchor for
    /// the same key must give the same result in either order.
    #[test]
    fn anchor_order_does_not_matter() {
        let pki = TestPki::generate("Trust Test");
        let root = pki.read("root.der");
        let short_root = reissue_short_lived(&pki, "root", "self",
            "basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n");
        let ica = pki.read("issuing-ca.der");
        for anchors in [vec![short_root.clone(), root.clone()], vec![root.clone(), short_root.clone()]] {
            let trust = TrustList { anchors, skipped: 0 };
            // Two days from now the short-lived root has expired; the other is valid.
            validate_issuing_chain(&[ica.clone()], &trust, two_days_from_now()).unwrap();
        }
    }

    #[test]
    fn issuer_discovery_order_does_not_matter() {
        let pki = TestPki::generate("Trust Test");
        let ica = pki.read("issuing-ca.der");
        let short_ica = reissue_short_lived(&pki, "issuing-ca", "root",
            "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n");
        let signer = pki.read("signer.der");
        for anchors in [vec![short_ica.clone(), ica.clone()], vec![ica.clone(), short_ica.clone()]] {
            let trust = TrustList { anchors, skipped: 0 };
            assert_eq!(issuing_path_for(&signer, &[], &trust, two_days_from_now()).unwrap(), vec![ica.clone()]);
        }
    }

    #[test]
    fn ca_with_eku_not_allowing_claim_signing_is_rejected() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("root.pem")).unwrap();
        for (name, eku) in [("crit-server", "critical,serverAuth"), ("server", "serverAuth"), ("tsa", "timeStamping")] {
            let ca = issue_ca(&pki, name, "root",
                &format!("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\nextendedKeyUsage={eku}\n"));
            let err = validate_issuing_chain(&[ca], &trust, now()).unwrap_err();
            assert!(format!("{err:#}").contains("does not allow C2PA claim signing"), "{name}: {err:#}");
        }
    }

    #[test]
    fn ca_with_malformed_critical_eku_is_rejected() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("root.pem")).unwrap();
        // DER NULL where a SEQUENCE of OIDs is required.
        let ca = issue_ca(&pki, "bad-eku", "root",
            "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\n2.5.29.37=critical,DER:05:00\n");
        let err = validate_issuing_chain(&[ca], &trust, now()).unwrap_err();
        assert!(format!("{err:#}").contains("invalid extendedKeyUsage"), "{err:#}");
    }

    #[test]
    fn ca_with_claim_signing_eku_is_accepted() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("root.pem")).unwrap();
        // As on a real C2PA issuing CA: email protection plus C2PA claim signing.
        let ca = issue_ca(&pki, "c2pa-eku", "root",
            "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\nextendedKeyUsage=emailProtection,1.3.6.1.4.1.62558.2.1\n");
        validate_issuing_chain(&[ca], &trust, now()).unwrap();
    }

    #[test]
    fn spki_key_id_survives_ca_certificate_renewal() {
        let pki = TestPki::generate("Trust Test");
        // Re-issue the issuing CA certificate with the same key, as a renewal would.
        let dir = &pki.path;
        let run = |args: &[&str]| {
            let ok = std::process::Command::new("openssl").args(args).current_dir(dir)
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .status().unwrap().success();
            assert!(ok, "openssl {args:?} failed");
        };
        run(&["req", "-new", "-key", "issuing-ca.key", "-subj", "/C=US/O=Renewed/CN=Renewed Issuing CA", "-out", "renewed.csr"]);
        std::fs::write(dir.join("renewed.ext"), "basicConstraints=critical,CA:TRUE,pathlen:0\n").unwrap();
        run(&["x509", "-req", "-in", "renewed.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial",
              "-days", "30", "-extfile", "renewed.ext", "-outform", "DER", "-out", "renewed.der"]);

        let original = pki.read("issuing-ca.der");
        let renewed = pki.read("renewed.der");
        assert_ne!(original, renewed);
        assert_eq!(spki_key_id(&original).unwrap(), spki_key_id(&renewed).unwrap());
        assert_ne!(spki_key_id(&original).unwrap(), spki_key_id(&pki.read("root.der")).unwrap());
    }
}
