//! Fixtures shared by more than one test binary.
//!
//! Each binary compiles this module whole, so single-use helpers belong next to the test
//! that needs them rather than here.

#![allow(dead_code)]

use std::path::PathBuf;

pub type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Install the aws-lc-rs default crypto provider once (idempotent across tests).
pub fn ensure_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A self-signed server pair plus a stand-in client-CA bundle, under a temp dir kept
/// alive by `_dir`.
pub struct CertFixture {
    _dir: tempfile::TempDir,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub client_ca: PathBuf,
}

impl CertFixture {
    /// Write `server.crt`/`server.key` for `san`, plus a separate self-signed
    /// `client-ca.crt`: loading a client-CA bundle only parses it into anchors, it does
    /// not check that the certificate is a CA.
    pub fn new(san: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        ensure_crypto_provider();
        let dir = tempfile::tempdir()?;
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
        let client_ca = dir.path().join("client-ca.crt");

        let server = rcgen::generate_simple_self_signed(vec![san.to_string()])?;
        std::fs::write(&cert, server.cert.pem())?;
        std::fs::write(&key, server.signing_key.serialize_pem())?;

        let ca = rcgen::generate_simple_self_signed(vec!["client-ca".to_string()])?;
        std::fs::write(&client_ca, ca.cert.pem())?;

        Ok(Self { _dir: dir, cert, key, client_ca })
    }
}
