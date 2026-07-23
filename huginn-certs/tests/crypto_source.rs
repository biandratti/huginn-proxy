//! `CryptoSource` abstraction: the resolver loads cert material from *any*
//! source, not just files. These tests wire a purely in-memory `CryptoSource`
//! (and a deliberately failing one) through `DynamicCertResolver::update` to show
//! the origin of the material is decoupled from resolution.

use std::sync::Arc;

use async_trait::async_trait;
use huginn_certs::{CertEntry, CertError, CryptoSource, DynamicCertResolver, ServerCertsKeys};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Install the aws-lc-rs default crypto provider once (idempotent across tests).
fn ensure_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Build cert/key material in memory (never written to disk) via rcgen.
fn certs_keys_in_memory(
    host: &str,
) -> Result<ServerCertsKeys, Box<dyn std::error::Error + Send + Sync>> {
    ensure_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![host.to_string()])?;

    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| c.into_owned())
        .collect();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?.clone_key();

    Ok(ServerCertsKeys { certs, key })
}

/// A `CryptoSource` that hands back pre-parsed material held in memory.
#[derive(Debug)]
struct InMemorySource(ServerCertsKeys);

#[async_trait]
impl CryptoSource for InMemorySource {
    async fn read(&self) -> Result<ServerCertsKeys, CertError> {
        Ok(self.0.clone())
    }
}

/// A `CryptoSource` that always fails, to exercise the error path without a file.
#[derive(Debug)]
struct FailingSource;

#[async_trait]
impl CryptoSource for FailingSource {
    async fn read(&self) -> Result<ServerCertsKeys, CertError> {
        Err(CertError::NoCertificates)
    }
}

/// A non-file source loads and resolves exactly like a `CryptoFileSource` would.
#[tokio::test]
async fn in_memory_source_loads_and_resolves() -> TestResult {
    let resolver = DynamicCertResolver::new(false);
    let source = Arc::new(InMemorySource(certs_keys_in_memory("mem.example.com")?));
    let entries = vec![CertEntry {
        host: Some("mem.example.com".to_string()),
        source,
        label: "mem.example.com".to_string(),
    }];

    let report = resolver.update(&entries).await;

    assert!(report.failed.is_empty(), "an in-memory cert must load");
    assert_eq!(report.loaded.len(), 1, "the in-memory domain went live");
    assert!(
        resolver.resolves_for(Some("mem.example.com")),
        "the in-memory cert resolves for its host"
    );
    Ok(())
}

/// A failing source is reported as `failed` and never resolves - the resolver
/// treats any `CryptoSource` uniformly, file-backed or not.
#[tokio::test]
async fn failing_source_is_reported_and_does_not_resolve() -> TestResult {
    ensure_crypto_provider();
    let resolver = DynamicCertResolver::new(false);
    let entries = vec![CertEntry {
        host: None,
        source: Arc::new(FailingSource),
        label: "_default_".to_string(),
    }];

    let report = resolver.update(&entries).await;

    assert!(report.loaded.is_empty(), "a failing source loads nothing");
    assert_eq!(report.failed.len(), 1, "the failing source is reported as failed");
    assert!(report.is_partial(), "a failed source makes the report partial");
    assert!(!resolver.resolves_for(None), "nothing resolves from a failing source");
    Ok(())
}

/// Different `CryptoSource` implementations can be mixed in one reload: an
/// in-memory catch-all serves alongside a failing named domain.
#[tokio::test]
async fn mixed_sources_in_one_reload() -> TestResult {
    let resolver = DynamicCertResolver::new(false);
    let entries = vec![
        CertEntry {
            host: None,
            source: Arc::new(InMemorySource(certs_keys_in_memory("catch.example.com")?)),
            label: "_default_".to_string(),
        },
        CertEntry {
            host: Some("api.example.com".to_string()),
            source: Arc::new(FailingSource),
            label: "api.example.com".to_string(),
        },
    ];

    let report = resolver.update(&entries).await;

    assert_eq!(report.loaded.len(), 1, "only the in-memory catch-all loads");
    assert_eq!(report.failed.len(), 1, "the failing named domain is reported");
    let (_, _, has_default) = resolver.cert_map_summary();
    assert!(has_default, "the in-memory catch-all populated the default slot");
    assert!(resolver.resolves_for(None), "no-SNI clients get the in-memory default cert");
    Ok(())
}
