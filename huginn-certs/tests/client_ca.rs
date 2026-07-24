//! Client-CA loading for mutual TLS via [`CryptoFileSource`].
//!
//! Exercises the optional client-CA bundle wired into `read_certs_and_keys`: a
//! file source with a client CA yields material where `is_mutual_tls()` is true
//! and carries the parsed trust anchors, while the absence of a bundle leaves the
//! domain without client auth. Missing or empty bundles fail loudly instead of
//! silently disabling client auth.

use std::path::PathBuf;

use huginn_certs::{CertError, CryptoFileSource, CryptoSource};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// A self-signed server pair plus a separate self-signed cert used as a client-CA
/// bundle, all under a temp dir kept alive by `_dir`.
struct Fixture {
    _dir: tempfile::TempDir,
    cert: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error + Send + Sync>> {
    let dir = tempfile::tempdir()?;
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    let client_ca = dir.path().join("client-ca.crt");

    let server = rcgen::generate_simple_self_signed(vec!["example.com".to_string()])?;
    std::fs::write(&cert, server.cert.pem())?;
    std::fs::write(&key, server.signing_key.serialize_pem())?;

    // A self-signed cert stands in as the client-CA bundle: loading only parses
    // the PEM into trust anchors, it does not validate CA-ness.
    let ca = rcgen::generate_simple_self_signed(vec!["client-ca".to_string()])?;
    std::fs::write(&client_ca, ca.cert.pem())?;

    Ok(Fixture { _dir: dir, cert, key, client_ca })
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
