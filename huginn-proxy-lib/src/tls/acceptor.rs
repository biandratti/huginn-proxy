use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::{TlsConfig, TlsOptions, TlsVersion};
use crate::error::{ProxyError, Result};
use crate::tls::cipher_suites::{is_cipher_suite_supported, supported_cipher_suites};
use crate::tls::curves::{is_curve_supported, supported_curves};

/// Builds a TLS acceptor from configuration
pub fn build_rustls(cfg: &TlsConfig) -> Result<TlsAcceptor> {
    let certs = {
        let bytes = std::fs::read(&cfg.cert_path)
            .map_err(|e| ProxyError::Tls(format!("Failed to read certificate: {e}")))?;
        CertificateDer::pem_slice_iter(&bytes)
            .collect::<std::result::Result<Vec<_>, rustls_pki_types::pem::Error>>()
            .map_err(|e| ProxyError::Tls(format!("Failed to parse certificates: {e}")))?
    };

    let key = {
        let bytes = std::fs::read(&cfg.key_path)
            .map_err(|e| ProxyError::Tls(format!("Failed to read key: {e}")))?;
        let mut keys: Vec<PrivateKeyDer<'_>> = PrivateKeyDer::pem_slice_iter(&bytes)
            .collect::<std::result::Result<Vec<_>, rustls_pki_types::pem::Error>>()
            .map_err(|e| ProxyError::Tls(format!("Failed to parse private key: {e}")))?;
        let Some(k) = keys.pop() else {
            return Err(ProxyError::NoPrivateKey);
        };
        k
    };

    validate_tls_options(&cfg.options)?;

    // Build server config with safe defaults
    // rustls 0.23 uses safe defaults which include TLS 1.2 and 1.3
    // The builder() method already uses safe defaults
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ProxyError::Tls(format!("Failed to build TLS config: {e}")))?;

    // Note: rustls 0.23 doesn't expose a direct API to filter cipher suites
    // or restrict TLS versions beyond safe defaults. The options are validated
    // and stored for future use when rustls API supports it, or for documentation
    // purposes to inform users about their configuration.

    // If cipher suites are specified, log a warning that they're not yet fully supported
    if !cfg.options.cipher_suites.is_empty() {
        tracing::warn!(
            "Cipher suite specification is not yet fully supported in rustls 0.23. \
            Using safe defaults. Specified cipher suites: {:?}",
            cfg.options.cipher_suites
        );
    }

    if !cfg.alpn.is_empty() {
        server.alpn_protocols = cfg.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }
    // If alpn is empty, leave server.alpn_protocols as default (empty = no ALPN)
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
