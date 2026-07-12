//! Shared TLS, X.509, and metrics helpers for the ACME integration test binaries.
//! Included by `acme.rs` and `acme_renewal.rs` via `#[path = "acme_helpers.rs"]`.

// Not every helper is called by both test binaries; suppress the resulting warnings.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

pub const PROXY_HOST: &str = "proxy.huginn.local";
pub const PROXY_PORT: u16 = 8443;
pub const PROXY_ADDR: &str = "127.0.0.1:8443";
pub const METRICS_URL: &str = "http://127.0.0.1:9090";

// ---------------------------------------------------------------------------
// TLS infrastructure
// ---------------------------------------------------------------------------

/// Test-only certificate verifier that accepts any server certificate so the
/// handshake completes and the presented chain can be inspected.
/// NEVER use this outside tests.
#[derive(Debug)]
pub struct AcceptAnyServerCert;

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

pub fn make_tls_connector(
) -> Result<(TlsConnector, ServerName<'static>), Box<dyn std::error::Error + Send + Sync>> {
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(PROXY_HOST.to_string())?;
    Ok((connector, server_name))
}

/// Open a TLS connection and return the raw leaf certificate DER bytes.
/// Single attempt, no retry.
pub async fn try_fetch_leaf(
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

/// Fetch the leaf certificate with retries (up to 30 s) to absorb the time Pebble
/// needs to issue the first certificate on proxy startup.
pub async fn fetch_leaf_certificate(
) -> Result<CertificateDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let (connector, server_name) = make_tls_connector()?;
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

/// Single-shot leaf fetch (no retry). Used when a cert is already expected to be serving.
pub async fn fetch_leaf_once(
) -> Result<CertificateDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let (connector, server_name) = make_tls_connector()?;
    try_fetch_leaf(&connector, &server_name).await
}

// ---------------------------------------------------------------------------
// X.509 helpers
// ---------------------------------------------------------------------------

/// Return the colon-separated hex serial number of a leaf DER certificate.
pub fn cert_serial(
    leaf: &CertificateDer,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| format!("failed to parse certificate: {e}"))?;
    let serial = cert
        .tbs_certificate
        .raw_serial()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(serial)
}

// ---------------------------------------------------------------------------
// Metrics helpers
// ---------------------------------------------------------------------------

pub async fn fetch_metrics() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("failed to build metrics client: {e}"))?;
    let resp = client
        .get(format!("{METRICS_URL}/metrics"))
        .send()
        .await
        .map_err(|e| format!("GET /metrics failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("metrics endpoint returned {}", resp.status()).into());
    }
    resp.text()
        .await
        .map_err(|e| format!("failed to read metrics body: {e}").into())
}

/// Extract a gauge/counter value from Prometheus text format.
///
/// Finds the first non-comment line whose name starts with `name` and all `labels` match.
pub fn acme_metric_value(body: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    body.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter(|l| l.starts_with(name))
        .find(|l| {
            labels
                .iter()
                .all(|(k, v)| l.contains(&format!("{k}=\"{v}\"")))
        })
        .and_then(|l| l.split_whitespace().last())
        .and_then(|v| v.parse().ok())
}
