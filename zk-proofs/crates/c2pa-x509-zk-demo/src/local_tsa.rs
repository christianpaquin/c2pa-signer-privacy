//! A local RFC 3161 time-stamp authority for test fixtures (roadmap E2b).
//!
//! Real C2PA signers get a time stamp from a TSA over HTTP. Fixtures that
//! mirror real assets need one too, without network access: [`LocalTsa`]
//! answers time-stamp requests with `openssl ts` and a test TSA certificate
//! (see `generate-test-pki.sh --mirror`), and [`TimeStampingSigner`] plugs it
//! into c2pa's signing, which then stores the token as `sigTst2` (claim v2).

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{Signer, SigningAlg};
use std::path::PathBuf;
use std::process::Command;

/// Space reserved in the claim signature for the time-stamp token, on top of
/// the signer's own reservation (a token with an EC TSA certificate is ~1.5 KB).
const TIME_STAMP_RESERVE: usize = 4096;

/// A test TSA: its certificate and private key (PEM).
#[derive(Clone, Debug)]
pub struct LocalTsa {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl LocalTsa {
    /// An RFC 3161 `TimeStampResp` (DER) over `message`, with a SHA-256
    /// message imprint and the TSA certificate included.
    pub fn time_stamp(&self, message: &[u8]) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir()?;
        let path = |name: &str| dir.path().join(name);
        std::fs::write(path("message.bin"), message)?;
        std::fs::write(path("serial"), "01\n")?;
        std::fs::write(
            path("tsa.cnf"),
            format!(
                "[tsa]\ndefault_tsa = local\n[local]\nserial = {}\nsigner_cert = {}\nsigner_key = {}\n\
                 signer_digest = sha256\ndefault_policy = 1.3.6.1.4.1.4146.2.3\ndigests = sha256, sha384\n\
                 accuracy = secs:1\ness_cert_id_alg = sha256\n",
                path("serial").display(),
                std::fs::canonicalize(&self.cert)?.display(),
                std::fs::canonicalize(&self.key)?.display(),
            ),
        )?;
        let openssl = |args: &[&str]| -> Result<()> {
            let out = Command::new("openssl").args(args).current_dir(dir.path()).output().context("failed to run openssl")?;
            if !out.status.success() {
                bail!("openssl {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr));
            }
            Ok(())
        };
        openssl(&["ts", "-query", "-data", "message.bin", "-sha256", "-cert", "-out", "request.tsq"])?;
        openssl(&["ts", "-reply", "-config", "tsa.cnf", "-queryfile", "request.tsq", "-out", "response.tsr"])?;
        Ok(std::fs::read(path("response.tsr"))?)
    }
}

/// A c2pa signer that time-stamps its signatures with a [`LocalTsa`].
pub struct TimeStampingSigner {
    inner: Box<dyn Signer>,
    tsa: LocalTsa,
}

impl TimeStampingSigner {
    pub fn new(inner: Box<dyn Signer>, tsa: LocalTsa) -> Self {
        Self { inner, tsa }
    }
}

impl Signer for TimeStampingSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        self.inner.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.inner.alg()
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        self.inner.certs()
    }

    fn reserve_size(&self) -> usize {
        self.inner.reserve_size() + TIME_STAMP_RESERVE
    }

    /// c2pa passes the countersignature structure to time-stamp (`sigTst2`
    /// for claim v2) and stores the token from the response.
    fn send_timestamp_request(&self, message: &[u8]) -> Option<c2pa::Result<Vec<u8>>> {
        Some(
            self.tsa
                .time_stamp(message)
                .map_err(|e| c2pa::Error::OtherError(anyhow!("local TSA: {e}").into())),
        )
    }
}
