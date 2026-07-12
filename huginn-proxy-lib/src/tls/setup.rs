use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::rustls::server::ResolvesServerCert;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;
use crate::error::Result;
use crate::tls::acceptor::build_server_config_with_resolver;

pub type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// Build a `TlsAcceptor` from static TLS options (ALPN, cipher suites, versions) and an
/// already-populated cert resolver.
///
/// `resolver` is a trait object so either the plain
/// [`DynamicCertResolver`](crate::tls::DynamicCertResolver) or the
/// [`CompositeResolver`](crate::tls::CompositeResolver) (static + per-host ACME) can be passed.
///
/// The acceptor is wrapped in an `ArcSwap` for API symmetry with the rest of the
/// proxy, but it is never swapped: certificate rotation happens *inside* the
/// resolver via `DynamicCertResolver::update` (driven by the config hot-reload
/// path in `proxy/reload.rs`), which swaps its own cert map without touching the
/// acceptor. ACME certs likewise rotate inside their resolver.
pub async fn build_tls_acceptor(
    tls_config: &TlsConfig,
    resolver: Arc<dyn ResolvesServerCert>,
    acme_active: bool,
) -> Result<SharedTlsAcceptor> {
    let acceptor = build_server_config_with_resolver(
        resolver,
        &tls_config.alpn,
        &tls_config.options,
        tls_config.client_auth.as_ref(),
        &tls_config.session_resumption,
        acme_active,
    )?;

    Ok(Arc::new(ArcSwap::new(Arc::new(acceptor))))
}
