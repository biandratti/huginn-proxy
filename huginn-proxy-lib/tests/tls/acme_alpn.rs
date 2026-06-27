//! ALPN wiring for the ACME TLS-ALPN-01 challenge: when `acme_active` is set, the acceptor
//! must offer `acme-tls/1` so the validation handshake can negotiate it. Verified end-to-end
//! with a real in-memory rustls handshake (not by introspecting the `ServerConfig`, which
//! exposes no public accessor for `alpn_protocols`).

use std::sync::Arc;

use huginn_proxy_lib::config::{ClientAuth, Domain, TlsOptions};
use huginn_proxy_lib::telemetry::Metrics;
use huginn_proxy_lib::tls::{build_server_config_with_resolver, DynamicCertResolver};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::helpers::create_valid_test_cert;

/// Run a TLS handshake over an in-memory duplex where the server acceptor is built with
/// `acme_active` and the client offers exactly `client_alpn`. Returns the ALPN protocol the
/// client negotiated (`None` if none) on success, or `Err` if the handshake failed.
async fn handshake_negotiated_alpn(
    acme_active: bool,
    client_alpn: &[&[u8]],
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    // Server: SNI cert resolver populated with the self-signed "localhost" cert.
    let resolver = Arc::new(DynamicCertResolver::new(false));
    let domain = Domain {
        host: Some("localhost".to_string()),
        cert_path: Some(cert_path.display().to_string()),
        key_path: Some(key_path.display().to_string()),
        acme: false,
        headers: None,
        security: None,
        fingerprinting: None,
        routes: vec![],
    };
    let report = resolver.update(&[domain], &Metrics::new_noop()).await;
    assert_eq!(report.failed, 0, "test cert must load");

    let acceptor = build_server_config_with_resolver(
        resolver,
        &["h2".to_string()],
        &TlsOptions::default(),
        &ClientAuth::Disabled,
        &Default::default(),
        acme_active,
    )?;

    // Client: trust the self-signed cert, offer the requested ALPN protocol(s).
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&cert_path)? {
        roots.add(cert?)?;
    }
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = client_alpn.iter().map(|p| p.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(client_config));

    let (client_io, server_io) = tokio::io::duplex(16 * 1024);

    // Drive the server handshake (and a tiny read so it doesn't drop mid-handshake) in a task.
    let server = tokio::spawn(async move {
        let mut tls = acceptor.accept(server_io).await?;
        let mut buf = [0u8; 1];
        let _ = tls.read(&mut buf).await;
        Ok::<(), std::io::Error>(())
    });

    let server_name = ServerName::try_from("localhost")?;
    let connect_result = connector.connect(server_name, client_io).await;

    let _ = cleanup(&cert_path, &key_path);

    let mut tls = connect_result?;
    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    // Let the client finish so the server task's read returns cleanly.
    tls.shutdown().await?;
    let _ = server.await;

    Ok(negotiated)
}

fn cleanup(cert: &std::path::Path, key: &std::path::Path) -> std::io::Result<()> {
    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
    Ok(())
}

#[tokio::test]
async fn acme_tls_alpn_offered_when_active() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // Client offers ONLY acme-tls/1; it can only be negotiated if the server offers it too.
    let negotiated = handshake_negotiated_alpn(true, &[b"acme-tls/1"]).await?;
    assert_eq!(negotiated.as_deref(), Some(b"acme-tls/1".as_slice()));
    Ok(())
}

#[tokio::test]
async fn acme_tls_alpn_absent_when_inactive() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // Server offers only "h2"; a client offering only acme-tls/1 has no overlap, so rustls
    // aborts the handshake (no_application_protocol).
    let result = handshake_negotiated_alpn(false, &[b"acme-tls/1"]).await;
    assert!(result.is_err(), "handshake should fail when acme-tls/1 is not offered");
    Ok(())
}

#[tokio::test]
async fn normal_alpn_still_negotiates_with_acme_active(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // acme-tls/1 is additive: a normal client still negotiates h2 when ACME is active.
    let negotiated = handshake_negotiated_alpn(true, &[b"h2"]).await?;
    assert_eq!(negotiated.as_deref(), Some(b"h2".as_slice()));
    Ok(())
}
