//! Private-key file permission warning, exercised through the public
//! [`read_certs_and_keys`] path (Unix only).
//!
//! `read_certs_and_keys` emits a non-blocking `warn!` when the key file has
//! group/other permission bits set. These tests generate a real self-signed
//! pair, chmod the key, and assert on the captured warning while confirming the
//! load still succeeds (the check never gates loading).

#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use huginn_certs::read_certs_and_keys;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// A self-signed cert/key pair written to a temp dir kept alive by `_dir`.
struct TestCert {
    _dir: tempfile::TempDir,
    cert: PathBuf,
    key: PathBuf,
}

fn make_cert() -> Result<TestCert, Box<dyn std::error::Error + Send + Sync>> {
    let dir = tempfile::tempdir()?;
    let cert = dir.path().join("test.crt");
    let key = dir.path().join("test.key");

    let rcgen::CertifiedKey { cert: c, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::write(&cert, c.pem())?;
    std::fs::write(&key, signing_key.serialize_pem())?;

    Ok(TestCert { _dir: dir, cert, key })
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// `MakeWriter` that captures every line written by the `fmt` subscriber, so a
/// test can assert on the emitted warning text.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl LogCapture {
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|p| p.into_inner())).to_string()
    }
}

impl Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Read the pair with a thread-local `warn`-level subscriber installed, returning
/// whether the load succeeded and the captured log. `#[tokio::test]` runs on a
/// current-thread runtime, so `set_default` stays in effect across the `await`.
async fn read_capturing(cert: &Path, key: &Path) -> (bool, String) {
    let cap = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(cap.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let ok = read_certs_and_keys(cert, key).await.is_ok();
    (ok, cap.snapshot())
}

#[tokio::test]
async fn no_warning_for_0600() -> TestResult {
    let tc = make_cert()?;
    set_mode(&tc.key, 0o600)?;
    let (ok, log) = read_capturing(&tc.cert, &tc.key).await;
    assert!(ok, "valid material must load");
    assert!(log.is_empty(), "0600 must not produce a warning, got: {log}");
    Ok(())
}

#[tokio::test]
async fn no_warning_for_0400() -> TestResult {
    let tc = make_cert()?;
    set_mode(&tc.key, 0o400)?;
    let (ok, log) = read_capturing(&tc.cert, &tc.key).await;
    assert!(ok, "valid material must load");
    assert!(log.is_empty(), "0400 must not produce a warning, got: {log}");
    Ok(())
}

#[tokio::test]
async fn warns_for_group_readable_0640() -> TestResult {
    let tc = make_cert()?;
    set_mode(&tc.key, 0o640)?;
    let (ok, log) = read_capturing(&tc.cert, &tc.key).await;
    assert!(ok, "loose perms never gate loading");
    assert!(
        log.contains("loose permissions"),
        "0640 should warn about loose perms, got: {log}"
    );
    assert!(
        !log.contains("world-readable"),
        "0640 must not be flagged world-readable, got: {log}"
    );
    assert!(log.contains("640"), "warning must mention the offending mode, got: {log}");
    Ok(())
}

#[tokio::test]
async fn warns_world_readable_for_0644() -> TestResult {
    let tc = make_cert()?;
    set_mode(&tc.key, 0o644)?;
    let (ok, log) = read_capturing(&tc.cert, &tc.key).await;
    assert!(ok, "loose perms never gate loading");
    assert!(
        log.contains("world-readable"),
        "0644 should be flagged world-readable, got: {log}"
    );
    assert!(log.contains("644"), "warning must mention the offending mode, got: {log}");
    Ok(())
}

/// The permission check runs only after the certificate parses; a missing key
/// file makes `metadata` fail, so no warning is emitted and the load errors out.
#[tokio::test]
async fn missing_key_is_silent() -> TestResult {
    let tc = make_cert()?;
    std::fs::remove_file(&tc.key)?;
    let (ok, log) = read_capturing(&tc.cert, &tc.key).await;
    assert!(!ok, "a missing key file must fail the load");
    assert!(log.is_empty(), "a missing key path must not warn, got: {log}");
    Ok(())
}
