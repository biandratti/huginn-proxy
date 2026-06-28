mod acceptor;
mod acme_alpn;
mod cert_resolver;
mod cert_source;
mod cipher_curve_signature;
mod composite_resolver;
mod options;
mod session_resumption;

use std::sync::Arc;

use huginn_proxy_lib::config::{ClientAuth, TlsOptions};
use huginn_proxy_lib::tls::{build_server_config_with_resolver, DynamicCertResolver};
use tokio_rustls::TlsAcceptor;

/// Build a `TlsAcceptor` through the production resolver path, using a fresh
/// (empty) `DynamicCertResolver`. For tests that exercise TLS-option and
/// client-auth wiring (cipher suites, curves, ALPN, mTLS) rather than SNI cert
/// resolution, which is covered by `cert_resolver`.
pub fn build_acceptor(
    alpn: &[String],
    options: &TlsOptions,
    client_auth: Option<&ClientAuth>,
    acme_active: bool,
) -> huginn_proxy_lib::error::Result<TlsAcceptor> {
    crate::helpers::ensure_crypto_provider();
    build_server_config_with_resolver(
        Arc::new(DynamicCertResolver::new(false)),
        alpn,
        options,
        client_auth,
        &Default::default(),
        acme_active,
    )
}
