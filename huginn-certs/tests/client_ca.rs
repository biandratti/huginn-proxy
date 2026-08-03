//! Client-CA loading for mutual TLS via [`CryptoFileSource`].
//!
//! Exercises the optional client-CA bundle wired into `read_certs_and_keys`: a
//! file source with a client CA yields material where `is_mutual_tls()` is true
//! and carries the parsed trust anchors, while the absence of a bundle leaves the
//! domain without client auth. Missing or empty bundles fail loudly instead of
//! silently disabling client auth.

mod common;

use common::{CertFixture, TestResult};
use huginn_certs::{CertError, CryptoFileSource, CryptoSource};

fn fixture() -> Result<CertFixture, Box<dyn std::error::Error + Send + Sync>> {
    CertFixture::new("example.com")
}

/// Without a client-CA bundle the material carries no anchors and is not mTLS.
#[tokio::test]
async fn no_client_ca_means_no_mutual_tls() -> TestResult {
    let fx = fixture()?;
    let material = CryptoFileSource::new(&fx.cert, &fx.key).read().await?;
    assert!(!material.is_mutual_tls(), "a source without a client CA is not mTLS");
    assert!(material.client_ca_certs.is_none(), "no client-CA anchors were loaded");
    Ok(())
}

/// A client-CA bundle turns the domain into mTLS and its anchors are parsed.
#[tokio::test]
async fn client_ca_enables_mutual_tls() -> TestResult {
    let fx = fixture()?;
    let material = CryptoFileSource::new(&fx.cert, &fx.key)
        .with_client_ca(&fx.client_ca)
        .read()
        .await?;
    assert!(material.is_mutual_tls(), "a source with a client CA is mTLS");
    let anchors = material
        .client_ca_certs
        .as_ref()
        .ok_or("client-CA anchors present")?;
    assert_eq!(anchors.len(), 1, "the single CA cert was parsed");
    Ok(())
}

/// A configured-but-missing client-CA file fails loudly as an I/O error.
#[tokio::test]
async fn missing_client_ca_file_errors() -> TestResult {
    let fx = fixture()?;
    let missing = fx.cert.with_file_name("does-not-exist.crt");
    let result = CryptoFileSource::new(&fx.cert, &fx.key)
        .with_client_ca(&missing)
        .read()
        .await;
    assert!(
        matches!(result, Err(CertError::Io { .. })),
        "a missing client-CA file must be an Io error, got: {result:?}"
    );
    Ok(())
}

/// An empty client-CA bundle parses to zero anchors and fails with `NoClientCert`
/// rather than silently disabling client auth.
#[tokio::test]
async fn empty_client_ca_file_errors() -> TestResult {
    let fx = fixture()?;
    let empty = fx.cert.with_file_name("empty-ca.crt");
    std::fs::write(&empty, b"")?;
    let result = CryptoFileSource::new(&fx.cert, &fx.key)
        .with_client_ca(&empty)
        .read()
        .await;
    assert!(
        matches!(result, Err(CertError::NoClientCert)),
        "an empty client-CA bundle must fail with NoClientCert, got: {result:?}"
    );
    Ok(())
}
