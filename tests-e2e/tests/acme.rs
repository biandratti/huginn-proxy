//! ACME end-to-end test against a local Pebble ACME server.
//!
//! Requires `examples/docker-compose.acme.yml` to be running: the proxy terminates TLS on
//! `:8443` with a certificate it obtained from Pebble via TLS-ALPN-01, and proxies to a
//! `whoami` backend. Run with:
//!
//! ```bash
//! ./examples/acme/gen-pebble-ca.sh
//! docker compose -f examples/docker-compose.acme.yml up --build -d
//! cargo test -p tests-e2e --test acme
//! ```
//!
//! The two checks together prove a real ACME issuance: the served leaf is issued by Pebble (not a
//! static/default cert; the `:8443` listener has no file cert configured) and traffic flows
//! through it to the backend.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const PROXY_HOST: &str = "proxy.huginn.local";
const PROXY_PORT: u16 = 8443;
const PROXY_ADDR: &str = "127.0.0.1:8443";

/// Test-only certificate verifier that accepts any server certificate so the handshake completes
/// and the presented chain can be inspected. NEVER use this outside tests.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

/// Open a TLS connection to the proxy (SNI = `proxy.huginn.local`) and return the leaf
/// certificate it presents. Retries to absorb the few seconds it takes the proxy to obtain the
/// certificate from Pebble after startup.
async fn fetch_leaf_certificate(
) -> Result<CertificateDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(PROXY_HOST.to_string())?;

    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for _ in 0..60 {
        match try_fetch_leaf(&connector, &server_name).await {
            Ok(cert) => return Ok(cert),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(last_err.unwrap_or_else(|| "failed to fetch leaf certificate".into()))
}

async fn try_fetch_leaf(
    connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> Result<CertificateDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpStream::connect(PROXY_ADDR).await?;
    let tls = connector.connect(server_name.clone(), tcp).await?;
    let (_io, conn) = tls.get_ref();
    let chain = conn
        .peer_certificates()
        .ok_or("no peer certificates presented")?;
    let leaf = chain.first().ok_or("empty certificate chain")?;
    Ok(leaf.clone().into_owned())
}

#[tokio::test]
async fn acme_cert_is_issued_by_pebble_for_the_domain() -> TestResult {
    let leaf = fetch_leaf_certificate().await?;

    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| format!("failed to parse leaf certificate: {e}"))?;
    
    let issuer = cert.issuer().to_string();
    assert!(issuer.contains("Pebble"), "leaf issuer should be Pebble, got: {issuer}");

    // The certificate is for our domain (SAN, not just CN).
    let san = cert
        .subject_alternative_name()
        .map_err(|e| format!("failed to read SAN: {e}"))?
        .ok_or("leaf certificate has no SAN extension")?;
    let has_domain = san.value.general_names.iter().any(
        |gn| matches!(gn, x509_parser::extensions::GeneralName::DNSName(dns) if *dns == PROXY_HOST),
    );
    assert!(has_domain, "leaf SAN must include {PROXY_HOST}");

    Ok(())
}

#[tokio::test]
async fn acme_proxy_serves_traffic_with_issued_cert() -> TestResult {
    // Ensure issuance has happened before exercising the data path.
    let _ = fetch_leaf_certificate().await?;

    let addr: SocketAddr = PROXY_ADDR.parse()?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(PROXY_HOST, addr)
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .get(format!("https://{PROXY_HOST}:{PROXY_PORT}/"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200, "proxy should return 200 over the ACME cert");

    let body = resp.text().await?;
    assert!(body.contains("Hostname:"), "expected whoami echo body, got: {body}");

    Ok(())
}
