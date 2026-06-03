use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;
use crate::error::Result;
use crate::proxy::shutdown::{ServiceHandle, ShutdownWatch};
use crate::telemetry::Metrics;

pub type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// Result of TLS setup.
pub struct TlsSetup {
    pub acceptor: SharedTlsAcceptor,
    pub reload_handle: Option<ServiceHandle>,
}

/// Setup the TLS acceptor from static TLS options (ALPN, cipher suites, versions).
///
/// Cert loading is handled by `DynamicCertResolver` (Step 2).
///
/// TODO(step2): inject `Arc<DynamicCertResolver>`, build `ServerConfig` with
/// `with_cert_resolver`, and remove this stub error.
pub async fn setup_tls_with_hot_reload(
    _tls_config: &TlsConfig,
    _watch: bool,
    _watch_delay_secs: u32,
    _metrics: Arc<Metrics>,
    _shutdown_rx: ShutdownWatch,
) -> Result<TlsSetup> {
    Err(crate::error::ProxyError::Config(
        "TLS cert loading via domains not yet implemented — complete Step 2 (DynamicCertResolver)"
            .to_string(),
    ))
}
