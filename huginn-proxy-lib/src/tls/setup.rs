use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;
use crate::error::Result;
use crate::proxy::shutdown::{ServiceHandle, ShutdownWatch};
use crate::telemetry::Metrics;
use crate::tls::acceptor::build_server_config_with_resolver;
use crate::tls::cert_resolver::DynamicCertResolver;

pub type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// Result of TLS setup.
///
/// `reload_handle` is always `None` in the new model — cert hot-reload is driven
/// by `DynamicCertResolver::update()` called from the config hot-reload path
/// (`proxy/reload.rs::try_reload`), not by an independent file watcher.
pub struct TlsSetup {
    pub acceptor: SharedTlsAcceptor,
    pub reload_handle: Option<ServiceHandle>,
}

/// Build a `TlsAcceptor` from static TLS options (ALPN, cipher suites, versions) and
/// an already-populated `DynamicCertResolver`.
///
/// The `_watch` / `_watch_delay_secs` / `_shutdown_rx` parameters are kept for API
/// compatibility but are unused: cert rotation is handled via config hot-reload
/// (`try_reload` calls `DynamicCertResolver::update`), not a per-file watcher.
pub async fn setup_tls_with_hot_reload(
    tls_config: &TlsConfig,
    resolver: Arc<DynamicCertResolver>,
    _watch: bool,
    _watch_delay_secs: u32,
    _metrics: Arc<Metrics>,
    _shutdown_rx: ShutdownWatch,
) -> Result<TlsSetup> {
    let acceptor = build_server_config_with_resolver(
        resolver,
        &tls_config.alpn,
        &tls_config.options,
        &tls_config.client_auth,
        &tls_config.session_resumption,
    )?;

    Ok(TlsSetup { acceptor: Arc::new(ArcSwap::new(Arc::new(acceptor))), reload_handle: None })
}
