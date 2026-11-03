//! Test helper: generate a C2PA-like test PKI with generate-test-pki.sh.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A generated PKI (root -> issuing CA -> signer) in a temporary directory,
/// deleted on drop. `name` keeps independent PKIs distinguishable.
pub struct TestPki {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
}

impl TestPki {
    pub fn generate(name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../generate-test-pki.sh");
        let status = Command::new("bash")
            .arg(script)
            .arg(dir.path())
            .arg(name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "generate-test-pki.sh failed");
        let path = dir.path().to_path_buf();
        Self { _dir: dir, path }
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.file(name)).unwrap()
    }
}
