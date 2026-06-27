use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use tokio_rustls::rustls::crypto::aws_lc_rs as aws_lc_provider;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::server::ResolvesServerCert;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::{ClientAuth, TlsOptions, TlsVersion};
use crate::error::{ProxyError, Result};
use crate::tls::cipher_suites::{
    is_cipher_suite_supported, resolve_cipher_suites, supported_cipher_suites,
};
use crate::tls::curves::{is_curve_supported, supported_curves};
use crate::tls::session_resumption::configure_session_resumption;

/// Loads CA certificates from a PEM file for client authentication
fn load_ca_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path)
        .map_err(|e| ProxyError::Tls(format!("Failed to read client CA certificate: {e}")))?;

    CertificateDer::pem_slice_iter(&bytes)
        .collect::<std::result::Result<Vec<_>, rustls_pki_types::pem::Error>>()
        .map_err(|e| ProxyError::Tls(format!("Failed to parse client CA certificates: {e}")))
}

/// Builds a `ServerConfig` that uses a `DynamicCertResolver` for SNI-based cert selection.
///
/// Cipher suites, ALPN, client auth, and session resumption are all applied here; cert
/// provisioning is delegated to the resolver (populated via `DynamicCertResolver::update`).
///
/// When `acme_active` is `true`, the `acme-tls/1` protocol is appended to the offered ALPN
/// list. This is required for the ACME TLS-ALPN-01 challenge: rustls must negotiate
/// `acme-tls/1` for the validation handshake before the `ClientHello` reaches the resolver,
/// otherwise it aborts ALPN negotiation. It is harmless to normal clients, which never
/// request it. The flag is a runtime bool (not a `cfg` feature) because the `acme` feature
/// lives in the binary crate, not in this library.
pub fn build_server_config_with_resolver(
    resolver: Arc<dyn ResolvesServerCert>,
    alpn: &[String],
    options: &TlsOptions,
    client_auth: &ClientAuth,
    session_resumption: &crate::config::SessionResumptionConfig,
    acme_active: bool,
) -> Result<TlsAcceptor> {
    validate_tls_options(options)?;

    let provider = if options.cipher_suites.is_empty() {
        aws_lc_provider::default_provider()
    } else {
        CryptoProvider {
            cipher_suites: resolve_cipher_suites(&options.cipher_suites),
            ..aws_lc_provider::default_provider()
        }
    };

    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| ProxyError::Tls(format!("Failed to set TLS protocol versions: {e}")))?;

    let mut server = match client_auth {
        ClientAuth::Required { ca_cert_path } => {
            let client_ca_certs = load_ca_certs(ca_cert_path)?;
            let mut root_store = RootCertStore::empty();
            for cert in client_ca_certs {
                root_store
                    .add(cert)
                    .map_err(|e| ProxyError::Tls(format!("Failed to add CA certificate: {e}")))?;
            }
            let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| ProxyError::Tls(format!("Failed to build client verifier: {e}")))?;
            builder
                .with_client_cert_verifier(client_verifier)
                .with_cert_resolver(resolver)
        }
        ClientAuth::Disabled => builder.with_no_client_auth().with_cert_resolver(resolver),
    };

    let mut alpn_protocols: Vec<Vec<u8>> = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    if acme_active {
        // Announce the TLS-ALPN-01 challenge protocol so the validation handshake can
        // negotiate it; the per-host ACME resolver then serves the challenge cert.
        alpn_protocols.push(b"acme-tls/1".to_vec());
    }
    if !alpn_protocols.is_empty() {
        server.alpn_protocols = alpn_protocols;
    }

    configure_session_resumption(&mut server, session_resumption);

    Ok(TlsAcceptor::from(Arc::new(server)))
}

pub fn validate_tls_options(options: &TlsOptions) -> Result<()> {
    validate_tls_options_impl(options)
}

fn validate_tls_options_impl(options: &TlsOptions) -> Result<()> {
    if let (Some(min), Some(max)) = (options.min_version, options.max_version) {
        if matches!((min, max), (TlsVersion::V1_3, TlsVersion::V1_2)) {
            return Err(ProxyError::Tls(
                "min_version (1.3) cannot be greater than max_version (1.2)".to_string(),
            ));
        }
    }

    if !options.versions.is_empty()
        && (options.min_version.is_some() || options.max_version.is_some())
    {
        return Err(ProxyError::Tls(
            "Cannot specify both 'versions' and 'min_version'/'max_version'. \
            Use either 'versions' or 'min_version'/'max_version'."
                .to_string(),
        ));
    }

    for suite_name in &options.cipher_suites {
        if suite_name.is_empty() {
            return Err(ProxyError::Tls("Cipher suite name cannot be empty".to_string()));
        }
        if !is_cipher_suite_supported(suite_name) {
            return Err(ProxyError::Tls(format!(
                "Cipher suite '{}' is not supported by rustls. \
                Supported cipher suites: {}",
                suite_name,
                supported_cipher_suites().join(", ")
            )));
        }
    }

    for curve_name in &options.curve_preferences {
        if curve_name.is_empty() {
            return Err(ProxyError::Tls("Curve name cannot be empty".to_string()));
        }
        if !is_curve_supported(curve_name) {
            return Err(ProxyError::Tls(format!(
                "Curve '{}' is not supported by rustls. \
                Supported curves: {}",
                curve_name,
                supported_curves().join(", ")
            )));
        }
    }

    Ok(())
}
