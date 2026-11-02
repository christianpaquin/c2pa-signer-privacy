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
/// intermediates) against a trust list at Unix time `at`. Succeeds when the
/// chain reaches a trust anchor: either a certificate in the chain is itself
/// an anchor, or the last one is issued by an anchor.
pub fn validate_issuing_chain(chain: &[Vec<u8>], trust: &TrustList, at: u64) -> Result<()> {
    if chain.is_empty() {
        bail!("issuing chain is empty");
    }
    for (i, der) in chain.iter().enumerate() {
        let cert = parse(der)?;
        check_ca(&cert, at).with_context(|| format!("issuing chain certificate {i}"))?;
        if trust.is_anchor(der) {
            return Ok(());
        }
        match chain.get(i + 1) {
            Some(next) => verify_issued_by(der, next)
                .with_context(|| format!("issuing chain certificate {i} is not issued by certificate {}", i + 1))?,
            None => {
                let anchor = trust
                    .anchors
                    .iter()
                    .find(|a| verify_issued_by(der, a).is_ok())
                    .ok_or_else(|| anyhow!("issuing chain does not chain to the trust list"))?;
                check_ca(&parse(anchor)?, at).context("trust anchor")?;
                return Ok(());
            }
        }
    }
    unreachable!("loop returns on the last certificate")
}

/// Find the issuing chain to embed for `leaf`: the provided intermediates if
/// the first one issued `leaf`, otherwise the trust anchor that did.
pub fn issuing_chain_for(leaf_der: &[u8], intermediates: &[Vec<u8>], trust: &TrustList) -> Result<Vec<Vec<u8>>> {
    if let Some(first) = intermediates.first() {
        if verify_issued_by(leaf_der, first).is_ok() {
            return Ok(intermediates.to_vec());
        }
    }
    trust
        .anchors
        .iter()
        .find(|a| verify_issued_by(leaf_der, a).is_ok())
        .map(|a| vec![a.clone()])
        .ok_or_else(|| anyhow!("no certificate in the chain or trust list issued the signer certificate"))
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

/// The certificate must be a CA and valid at `at`.
fn check_ca(cert: &Certificate, at: u64) -> Result<()> {
    use x509_cert::ext::pkix::BasicConstraints;
    let tbs = &cert.tbs_certificate;
    let is_ca = tbs
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS)
        .and_then(|e| BasicConstraints::from_der(e.extn_value.as_bytes()).ok())
        .is_some_and(|bc| bc.ca);
    if !is_ca {
        bail!("{} is not a CA certificate", tbs.subject);
    }
    let not_before = tbs.validity.not_before.to_unix_duration().as_secs();
    let not_after = tbs.validity.not_after.to_unix_duration().as_secs();
    if at < not_before || at > not_after {
        bail!("{} is not valid at the verification time", tbs.subject);
    }
    Ok(())
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

    #[test]
    fn issuing_chain_for_signer_prefers_provided_intermediates_then_anchors() {
        let pki = TestPki::generate("Trust Test");
        let trust = TrustList::from_file(&pki.file("trust-list.pem")).unwrap();
        let signer = pki.read("signer.der");
        let ica = pki.read("issuing-ca.der");
        assert_eq!(issuing_chain_for(&signer, &[ica.clone()], &trust).unwrap(), vec![ica.clone()]);
        // Not in the signed chain: found in the trust list instead.
        assert_eq!(issuing_chain_for(&signer, &[], &trust).unwrap(), vec![ica]);
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
