use crate::backend::health_check::HealthRegistry;
use crate::backend::{BackendSelector, UpstreamGateway};
use crate::config::{FingerprintConfig, KeepAliveConfig, ProxyProtocolMode};
use crate::fingerprinting::{SynResult, TcpObservation};
use crate::proxy::connection::{ConnectionError, ConnectionManager};
use crate::proxy::protocol::{
    detect_proxy_protocol, normalize_mapped_ipv4, read_proxy_header_v1, read_proxy_header_v2,
    ProxyProtocolDetection, ProxySource,
};
use crate::proxy::reload::{SharedClientPool, SharedDynamicConfig, SharedRateLimiter};
use crate::proxy::security_context::SecurityContext;
use crate::proxy::transport::{
    handle_plain_connection, handle_tls_connection, PlainConnectionConfig, TlsConnectionConfig,
};
use crate::telemetry::values as metric_values;
use crate::telemetry::Metrics;
use crate::tls::setup::SharedTlsAcceptor;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use ipnet::IpNet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration, Instant};
use tracing::{debug, trace, warn};

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
    /// PROXY protocol v2 handling (static config). `Off` = today's behavior.
    pub proxy_protocol: ProxyProtocolMode,
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

        // TODO: potential hang at shutdown, if the shutdown signal is set after the check above
        // but before this await, the loop blocks until a new client connects. Fix: use
        // tokio::select! to race listener.accept() against a shutdown notification.
        let (mut stream, socket_peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, ?addr, "accept error");
                continue;
            }
        };

        // Connection accounting is keyed on the real TCP peer, never the PROXY-declared client.
        let guard = match connection_manager.try_accept(socket_peer, &ctx.metrics) {
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

        // Loaded once here so the PROXY-protocol trust gate and the rest of the loop body share
        // a single config snapshot (`trusted_proxies` lives in dynamic config).
        let dynamic = ctx.dynamic_cfg.load();

        // Resolve the effective client peer. Behind an L4 passthrough proxy this recovers the
        // original client `(src_ip, src_port)` from the PROXY v2 header so the eBPF SYN lookup,
        // `X-Forwarded-*`, rate-limiting, IP filtering and logs all see the real client.
        let peer =
            match resolve_peer(&ctx, &dynamic.security.trusted_proxies, &mut stream, socket_peer)
                .await
            {
                Some(p) => p,
                None => continue, // dropped (require + untrusted, bad header, or timeout)
            };

        let syn_start = Instant::now();
        let syn_result = ctx.syn_probe.as_ref().map(|probe| probe(peer));
        let syn_duration = syn_start.elapsed().as_secs_f64();
        let syn_fingerprint: Option<TcpObservation> = syn_result.as_ref().and_then(|r| {
            ctx.metrics
                .record_tcp_syn_fingerprint(r.label(), syn_duration);
            r.observation().cloned()
        });

        let rate_mgr = (**ctx.rate_limiter.load()).clone();
        let security = SecurityContext::new(
            dynamic.security.headers.clone(),
            dynamic.security.ip_filter.clone(),
            dynamic.security.rate_limit.clone(),
            rate_mgr,
            dynamic.headers.clone(),
            dynamic.security.trusted_proxies.clone(),
        );
        let backends = Arc::clone(&dynamic.backends);
        let domains = Arc::clone(&dynamic.domains);
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
                        domains: domains.clone(),
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
                        domains,
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

/// Resolve the effective client peer, honoring `listen.proxy_protocol`.
///
/// Returns `Some(peer)` to proceed (`peer` is the PROXY-declared client when a trusted peer sent
/// a valid header, otherwise the socket peer) or `None` when the connection must be dropped
/// (`require` + untrusted peer, malformed header, or a read timeout).
///
/// Security boundary: a PROXY header is parsed **only** when the immediate socket peer is in
/// `trusted_proxies`. Untrusted peers are never parsed, so a direct attacker cannot forge a
/// header to spoof its source (classic PROXY-protocol spoofing).
async fn resolve_peer(
    ctx: &AcceptContext,
    trusted_proxies: &[IpNet],
    stream: &mut TcpStream,
    socket_peer: SocketAddr,
) -> Option<SocketAddr> {
    let timeout_dur = ctx.tls_handshake_timeout;

    match ctx.proxy_protocol {
        ProxyProtocolMode::Off => Some(socket_peer),

        mode => {
            // Normalize an IPv4-mapped IPv6 peer (dual-stack `[::]` listener accepting IPv4) so a
            // configured IPv4 CIDR matches; otherwise the trust gate silently fails.
            let peer_ip = normalize_mapped_ipv4(socket_peer.ip());
            let trusted =
                !trusted_proxies.is_empty() && trusted_proxies.iter().any(|n| n.contains(&peer_ip));

            // Untrusted peers are never parsed: `optional` serves them as a direct client;
            // `require` drops them since the listener is declared to only serve a known proxy.
            // An untrusted `optional` peer is ordinary direct traffic (never a PROXY candidate),
            // so it is intentionally not counted in any proxy_protocol metric.
            if !trusted {
                return match mode {
                    ProxyProtocolMode::Require => {
                        ctx.metrics.record_proxy_protocol_dropped(
                            metric_values::PROXY_PROTOCOL_DROP_UNTRUSTED_REQUIRE,
                        );
                        warn!(?socket_peer, "drop: proxy_protocol=require + untrusted peer");
                        None
                    }
                    _ => Some(socket_peer),
                };
            }

            // Trusted peer: detect the header version without consuming so a missing header (in
            // `optional`) leaves the stream intact for the TLS ClientHello.
            let detection = match timeout(timeout_dur, detect_proxy_protocol(stream)).await {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => {
                    ctx.metrics.record_proxy_protocol_dropped(
                        metric_values::PROXY_PROTOCOL_DROP_BAD_HEADER,
                    );
                    warn!(?socket_peer, error = %e, "PROXY detect read error");
                    return None;
                }
                Err(_) => {
                    ctx.metrics
                        .record_proxy_protocol_dropped(metric_values::PROXY_PROTOCOL_DROP_TIMEOUT);
                    warn!(?socket_peer, "PROXY detect timeout");
                    return None;
                }
            };

            // Dispatch to the matching reader. `None` means no header: `optional` serves the peer
            // as a direct client, `require` drops it (listener is declared to only serve a proxy).
            let read_result = match detection {
                ProxyProtocolDetection::None => {
                    return match mode {
                        ProxyProtocolMode::Require => {
                            ctx.metrics.record_proxy_protocol_dropped(
                                metric_values::PROXY_PROTOCOL_DROP_BAD_HEADER,
                            );
                            warn!(?socket_peer, "drop: proxy_protocol=require + no PROXY header");
                            None
                        }
                        _ => {
                            ctx.metrics.record_proxy_protocol_passthrough();
                            trace!(
                                socket_peer = %socket_peer,
                                "PROXY optional: no header, serving as direct client"
                            );
                            Some(socket_peer)
                        }
                    };
                }
                ProxyProtocolDetection::V1 => {
                    timeout(timeout_dur, read_proxy_header_v1(stream)).await
                }
                ProxyProtocolDetection::V2 => {
                    timeout(timeout_dur, read_proxy_header_v2(stream)).await
                }
            };

            match read_result {
                Ok(Ok(ProxySource::Client(src))) => {
                    ctx.metrics.record_proxy_protocol_accepted();
                    debug!(
                        socket_peer = %socket_peer,
                        real_client = %src,
                        "PROXY header: real client recovered"
                    );
                    Some(src)
                }
                // LOCAL (v2) / UNKNOWN (v1): the emitter deliberately signalled no client (e.g.
                // health checks) → fall back to the socket peer, quietly (expected).
                Ok(Ok(ProxySource::Local)) => {
                    ctx.metrics.record_proxy_protocol_passthrough();
                    trace!(
                        socket_peer = %socket_peer,
                        "PROXY LOCAL/UNKNOWN command: keeping socket peer"
                    );
                    Some(socket_peer)
                }
                // PROXY command but a non-IP address family: we expected a client address and got
                // none. Serve the connection on the socket peer, but warn + meter — correlation
                // (eBPF SYN, X-Forwarded-*, backend signature validation) is degraded here.
                Ok(Ok(ProxySource::NoClientAddr)) => {
                    ctx.metrics.record_proxy_protocol_no_client_addr();
                    warn!(
                        socket_peer = %socket_peer,
                        "PROXY header carried a non-IP address family (AF_UNSPEC/AF_UNIX): no client \
                         address recovered, correlation degraded; keeping socket peer"
                    );
                    Some(socket_peer)
                }
                Ok(Err(e)) => {
                    ctx.metrics.record_proxy_protocol_dropped(
                        metric_values::PROXY_PROTOCOL_DROP_BAD_HEADER,
                    );
                    warn!(?socket_peer, error = %e, "bad PROXY header");
                    None
                }
                Err(_) => {
                    ctx.metrics
                        .record_proxy_protocol_dropped(metric_values::PROXY_PROTOCOL_DROP_TIMEOUT);
                    warn!(?socket_peer, "PROXY header read timeout");
                    None
                }
            }
        }
    }
}
