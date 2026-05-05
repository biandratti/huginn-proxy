use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};
use tracing::warn;

use crate::backend::health_check::HealthRegistry;
use crate::backend::{BackendSelector, UpstreamGateway};
use crate::config::{FingerprintConfig, KeepAliveConfig};
use crate::fingerprinting::{SynResult, TcpObservation};
use crate::proxy::connection::{ConnectionError, ConnectionManager};
use crate::proxy::reload::{SharedClientPool, SharedDynamicConfig, SharedRateLimiter};
use crate::proxy::security_context::SecurityContext;
use crate::proxy::transport::{
    handle_plain_connection, handle_tls_connection, PlainConnectionConfig, TlsConnectionConfig,
};
use crate::telemetry::Metrics;
use crate::tls::setup::SharedTlsAcceptor;

/// Callback type for TCP SYN fingerprint lookup.
///
/// Returns a [`SynResult`] so the server can record a precise metric label.
/// Implemented by `huginn-proxy` when the `ebpf-tcp` feature is enabled.
pub type SynProbe = Arc<dyn Fn(SocketAddr) -> SynResult + Send + Sync>;

/// Shared state for accept loops, built once in `run()` and cloned per listener.
pub struct AcceptContext {
    pub dynamic_cfg: SharedDynamicConfig,
    pub rate_limiter: SharedRateLimiter,
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    pub fingerprint_config: FingerprintConfig,
    pub keep_alive_config: KeepAliveConfig,
    pub metrics: Arc<Metrics>,
    pub client_pool: SharedClientPool,
    pub builder: ConnBuilder<TokioExecutor>,
    pub syn_probe: Option<SynProbe>,
    pub health_registry: Arc<HealthRegistry>,
    pub backend_selector: Arc<BackendSelector>,
    pub tls_handshake_timeout: Duration,
    pub connection_handling_timeout: Duration,
}

pub async fn accept_loop(
    addr: SocketAddr,
    listener: TcpListener,
    shutdown_signal: Arc<AtomicUsize>,
    connection_manager: Arc<ConnectionManager>,
    ctx: Arc<AcceptContext>,
) {
    loop {
        if shutdown_signal.load(Ordering::Relaxed) != 0 {
            break;
        }

        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, ?addr, "accept error");
                continue;
            }
        };

        let guard = match connection_manager.try_accept(peer, &ctx.metrics) {
            Ok(g) => g,
            Err(ConnectionError::Shutdown) => {
                drop(stream);
                break;
            }
            Err(ConnectionError::LimitExceeded { .. }) => {
                drop(stream);
                continue;
            }
        };

        let syn_start = Instant::now();
        let syn_result = ctx.syn_probe.as_ref().map(|probe| probe(peer));
        let syn_duration = syn_start.elapsed().as_secs_f64();
        let syn_fingerprint: Option<TcpObservation> = syn_result.as_ref().and_then(|r| {
            ctx.metrics
                .record_tcp_syn_fingerprint(r.label(), syn_duration);
            r.observation().cloned()
        });

        let dynamic = ctx.dynamic_cfg.load();
        let rate_mgr = (**ctx.rate_limiter.load()).clone();
        let security = SecurityContext::new(
            dynamic.security.headers.clone(),
            dynamic.security.ip_filter.clone(),
            dynamic.security.rate_limit.clone(),
            rate_mgr,
            dynamic.headers.clone(),
        );
        let backends = Arc::new(dynamic.backends.clone());
        let routes = dynamic.routes.clone();
        let preserve_host = dynamic.preserve_host;
        let upstream =
            UpstreamGateway::new(ctx.health_registry.clone(), ctx.backend_selector.clone());
        let ctx_task = Arc::clone(&ctx);

        tokio::spawn(async move {
            let _guard = guard;

            if let Some(ref tls_acceptor) = ctx_task.tls_acceptor {
                handle_tls_connection(
                    stream,
                    peer,
                    TlsConnectionConfig {
                        tls_acceptor: tls_acceptor.clone(),
                        fingerprint_config: ctx_task.fingerprint_config.clone(),
                        routes,
                        backends,
                        keep_alive: ctx_task.keep_alive_config.clone(),
                        security: security.clone(),
                        metrics: ctx_task.metrics.clone(),
                        builder: ctx_task.builder.clone(),
                        preserve_host,
                        tls_handshake_timeout: ctx_task.tls_handshake_timeout,
                        connection_handling_timeout: ctx_task.connection_handling_timeout,
                        client_pool: ctx_task.client_pool.load_full(),
                        syn_fingerprint: syn_fingerprint.clone(),
                        upstream: upstream.clone(),
                    },
                )
                .await;
            } else {
                handle_plain_connection(
                    stream,
                    peer,
                    PlainConnectionConfig {
                        routes,
                        backends,
                        keep_alive: ctx_task.keep_alive_config.clone(),
                        security,
                        metrics: ctx_task.metrics.clone(),
                        builder: ctx_task.builder.clone(),
                        preserve_host,
                        connection_handling_timeout: ctx_task.connection_handling_timeout,
                        client_pool: ctx_task.client_pool.load_full(),
                        syn_fingerprint,
                        upstream,
                    },
                )
                .await;
            }
        });
    }
}
