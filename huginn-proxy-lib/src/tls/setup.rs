use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;
use crate::error::Result;
use crate::tls::acceptor::build_server_config_with_resolver;
use crate::tls::cert_resolver::DynamicCertResolver;

pub type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// Build a `TlsAcceptor` from static TLS options (ALPN, cipher suites, versions) and
/// an already-populated [`DynamicCertResolver`].
///
/// The acceptor is wrapped in an `ArcSwap` for API symmetry with the rest of the
/// proxy, but it is never swapped: certificate rotation happens *inside* the
/// resolver via [`DynamicCertResolver::update`] (driven by the config hot-reload
/// path in `proxy/reload.rs`), which swaps its own cert map without touching the
/// acceptor.
pub async fn build_tls_acceptor(
    tls_config: &TlsConfig,
    resolver: Arc<DynamicCertResolver>,
) -> Result<SharedTlsAcceptor> {
    let acceptor = build_server_config_with_resolver(
        resolver,
        &tls_config.alpn,
        &tls_config.options,
        &tls_config.client_auth,
        &tls_config.session_resumption,
    )?;

    Ok(Arc::new(ArcSwap::new(Arc::new(acceptor))))
}
