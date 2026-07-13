use crate::backend::health_check::HealthRegistry;
use crate::backend::{BackendSelector, UpstreamGateway};
use crate::config::{FingerprintConfig, KeepAliveConfig, ProxyProtocolConfig, ProxyProtocolMode};
use crate::fingerprinting::{SynResult, TcpObservation};
use crate::proxy::connection::{ConnectionError, ConnectionManager};
use crate::proxy::protocol::{
    detect_proxy_protocol, normalize_mapped_ipv4, read_proxy_header_v1, read_proxy_header_v2,
    ProxyProtocolDetection, ProxyProtocolError, ProxySource,
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
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::error::Elapsed;
use tokio::time::{timeout, Duration, Instant};
use tracing::{debug, trace, warn};

/// Callback type for TCP SYN fingerprint lookup.
///
/// Returns a [`SynResult`] so the server can record a precise metric label.
/// Implemented by `huginn-proxy` when the `ebpf-tcp` feature is enabled.
pub type SynProbe = Arc<dyn Fn(SocketAddr) -> SynResult + Send + Sync>;

/// Runtime form of `listen.proxy_protocol`: the mode plus the effective header-read timeout,
/// resolved once in `server::run` (`header_timeout_ms == 0` mapped to
/// [`PROXY_HEADER_FALLBACK_TIMEOUT`]) rather than on every accepted connection.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedProxyProtocol {
    pub mode: ProxyProtocolMode,
    pub header_timeout: Duration,
}

impl ResolvedProxyProtocol {
    /// Resolve a listener's static [`ProxyProtocolConfig`] into this runtime form. See
    /// [`resolve_proxy_protocol_header_timeout`].
    pub fn resolve(config: ProxyProtocolConfig) -> Self {
        Self {
            mode: config.mode,
            header_timeout: resolve_proxy_protocol_header_timeout(config.header_timeout_ms),
        }
    }
}

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
    pub proxy_protocol: ResolvedProxyProtocol,
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
        let (stream, socket_peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, ?addr, "accept error");
                continue;
            }
        };

        // Connection accounting is keyed on the real TCP peer, never the PROXY-declared client.
        // Checked here (before spawning) so a full connection table never spawns tasks that
        // immediately drop.
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

        let ctx_task = Arc::clone(&ctx);
        tokio::spawn(async move {
            let _guard = guard;
            let mut stream = stream;

            // Load the latest config snapshot inside the task: the accept loop never blocks on
            // config access, and each connection sees the config current at the time it runs.
            let dynamic = ctx_task.dynamic_cfg.load();

            // Resolve the effective client peer. Runs inside the spawned task so that slow or
            // malicious peers cannot delay acceptance of subsequent connections: a peer
            // deliberately withholding the PROXY header up to the timeout (default 100 ms) would
            // otherwise serialize accepts on this listener.
            //
            // Behind an L4 passthrough proxy this recovers the original client `(src_ip, src_port)`
            // from the PROXY protocol header (v1 or v2) so the eBPF SYN lookup, `X-Forwarded-*`,
            // rate-limiting, IP filtering and logs all see the real client.
            let peer = match resolve_peer(
                ctx_task.proxy_protocol.mode,
                ctx_task.proxy_protocol.header_timeout,
                &ctx_task.metrics,
                &dynamic.security.trusted_proxies,
                &mut stream,
                socket_peer,
            )
            .await
            {
                Some(p) => p,
                None => return, // dropped (require + untrusted, bad header, or timeout)
            };

            let syn_start = Instant::now();
            let syn_result = ctx_task.syn_probe.as_ref().map(|probe| probe(peer));
            let syn_duration = syn_start.elapsed().as_secs_f64();
            let syn_fingerprint: Option<TcpObservation> = syn_result.as_ref().and_then(|r| {
                ctx_task
                    .metrics
                    .record_tcp_syn_fingerprint(r.label(), syn_duration);
                r.observation().cloned()
            });

            let rate_mgr = (**ctx_task.rate_limiter.load()).clone();
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
            let upstream = UpstreamGateway::new(
                ctx_task.health_registry.clone(),
                ctx_task.backend_selector.clone(),
            );

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

/// Fallback timeout applied when `listen.proxy_protocol.header_timeout_ms` is configured as `0`.
///
/// Covers the entire PROXY header resolution (the version-sniff peek loop plus the full header
/// read) so a trusted-but-slow-or-hostile peer cannot park a connection slot indefinitely. A
/// timeout here drops the connection **regardless of `proxy_protocol` mode** (including
/// `optional`; see `resolve_peer`'s detect-phase timeout arm), so this value is the worst-case
/// hold time per connection for every mode, not just `require`.
///
/// 1 s, not the 5 s used by the rust-rpxy reference: a legitimate PROXY-speaking peer writes the
/// header synchronously right after `connect()` (typically <5 ms), so even 1 s is a generous
/// margin over the honest case while keeping the worst case an order of magnitude tighter.
const PROXY_HEADER_FALLBACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Resolve `listen.proxy_protocol.header_timeout_ms` into the effective [`Duration`] passed to
/// [`resolve_peer`], mapping `0` to [`PROXY_HEADER_FALLBACK_TIMEOUT`].
///
/// Called once in [`ResolvedProxyProtocol::resolve`] (in turn called once in `server::run`)
/// rather than per-connection: the configured value is static (`proxy_protocol` itself requires a
/// restart to change), so there is no need to re-derive it on every accepted connection.
fn resolve_proxy_protocol_header_timeout(configured_ms: u64) -> Duration {
    if configured_ms == 0 {
        warn!(
            "listen.proxy_protocol.header_timeout_ms=0: falling back to {}s. This is not \
             recommended - a slow or hostile trusted peer can hold a connection slot for that \
             long while withholding the PROXY header.",
            PROXY_HEADER_FALLBACK_TIMEOUT.as_secs()
        );
        PROXY_HEADER_FALLBACK_TIMEOUT
    } else {
        Duration::from_millis(configured_ms)
    }
}

/// Whether `peer_ip` matches any CIDR in `trusted_proxies`.
///
/// The caller normalizes IPv4-mapped IPv6 first (a dual-stack listener bound to `[::]` reports an
/// incoming IPv4 connection as `::ffff:a.b.c.d`, which an `IpNet::V4` entry would never match).
fn is_trusted(peer_ip: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    !trusted_proxies.is_empty() && trusted_proxies.iter().any(|n| n.contains(&peer_ip))
}

/// Whether a passthrough outcome (non-`Require` mode, no PROXY source available) is worth
/// recording. An untrusted peer passing through is the common, unremarkable case when
/// `proxy_protocol=optional` serves both proxied and direct clients, so it stays silent; a
/// *trusted* peer that omitted the header is comparatively unusual (it is expected to always
/// speak the protocol), so that case is logged.
enum PassthroughNote {
    Silent,
    Logged,
}

/// `Require` drops the connection when no valid PROXY source is available; every other mode
/// falls back to `socket_peer`. Shared by the "untrusted peer" and "trusted peer, no header"
/// branches of [`resolve_peer`], which follow this same mode split but differ in drop
/// reason/message and in whether the passthrough itself is worth recording.
fn require_drops(
    mode: ProxyProtocolMode,
    metrics: &Metrics,
    socket_peer: SocketAddr,
    drop_reason: &'static str,
    drop_msg: &'static str,
    passthrough_note: PassthroughNote,
) -> Option<SocketAddr> {
    match mode {
        ProxyProtocolMode::Require => {
            metrics.record_proxy_protocol_dropped(drop_reason);
            warn!(?socket_peer, "{drop_msg}");
            None
        }
        _ => {
            if matches!(passthrough_note, PassthroughNote::Logged) {
                metrics.record_proxy_protocol_passthrough();
                trace!(
                    socket_peer = %socket_peer,
                    "PROXY optional: no header, serving as direct client"
                );
            }
            Some(socket_peer)
        }
    }
}

/// Maps a `read_proxy_header_v1`/`v2` outcome (already raced against `timeout_dur`) to the
/// effective peer, recording the metric and log line that matches each case.
fn peer_from_read_result(
    read_result: Result<Result<ProxySource, ProxyProtocolError>, Elapsed>,
    metrics: &Metrics,
    socket_peer: SocketAddr,
) -> Option<SocketAddr> {
    match read_result {
        Ok(Ok(ProxySource::Client(src))) => {
            metrics.record_proxy_protocol_accepted();
            debug!(
                socket_peer = %socket_peer,
                real_client = %src,
                "PROXY header: real client recovered"
            );
            Some(src)
        }
        Ok(Ok(ProxySource::Local)) => {
            metrics.record_proxy_protocol_passthrough();
            trace!(
                socket_peer = %socket_peer,
                "PROXY LOCAL/UNKNOWN command: keeping socket peer"
            );
            Some(socket_peer)
        }
        Ok(Ok(ProxySource::NoClientAddr)) => {
            metrics.record_proxy_protocol_no_client_addr();
            warn!(
                socket_peer = %socket_peer,
                "PROXY header carried a non-IP address family (AF_UNSPEC/AF_UNIX): no client \
                 address recovered, correlation degraded; keeping socket peer"
            );
            Some(socket_peer)
        }
        Ok(Err(e)) => {
            metrics.record_proxy_protocol_dropped(metric_values::PROXY_PROTOCOL_DROP_BAD_HEADER);
            warn!(?socket_peer, error = %e, "bad PROXY header");
            None
        }
        Err(_) => {
            metrics.record_proxy_protocol_dropped(metric_values::PROXY_PROTOCOL_DROP_TIMEOUT);
            warn!(?socket_peer, "PROXY header read timeout");
            None
        }
    }
}

/// Resolve the effective client peer, honoring `proxy_mode`.
///
/// Returns `Some(peer)` to proceed (`peer` is the PROXY-declared client when a trusted peer sent
/// a valid header, otherwise `socket_peer`) or `None` when the connection must be dropped
/// (`require` + untrusted peer, malformed header, or a read timeout).
///
/// Security boundary: a PROXY header is parsed **only** when the immediate socket peer is in
/// `trusted_proxies`. Untrusted peers are never parsed, so a direct attacker cannot forge a
/// header to spoof its source (classic PROXY-protocol spoofing).
///
/// Receives individual fields rather than `&AcceptContext` so it can be unit-tested without
/// constructing the full context.
pub async fn resolve_peer(
    proxy_mode: ProxyProtocolMode,
    timeout_dur: Duration,
    metrics: &Metrics,
    trusted_proxies: &[IpNet],
    stream: &mut TcpStream,
    socket_peer: SocketAddr,
) -> Option<SocketAddr> {
    let mode = match proxy_mode {
        ProxyProtocolMode::Off => return Some(socket_peer),
        mode => mode,
    };

    let peer_ip = normalize_mapped_ipv4(socket_peer.ip());
    if !is_trusted(peer_ip, trusted_proxies) {
        return require_drops(
            mode,
            metrics,
            socket_peer,
            metric_values::PROXY_PROTOCOL_DROP_UNTRUSTED_REQUIRE,
            "drop: proxy_protocol=require + untrusted peer",
            PassthroughNote::Silent,
        );
    }

    let detection = match timeout(timeout_dur, detect_proxy_protocol(stream)).await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            metrics.record_proxy_protocol_dropped(metric_values::PROXY_PROTOCOL_DROP_BAD_HEADER);
            warn!(?socket_peer, error = %e, "PROXY detect read error");
            return None;
        }
        Err(_) => {
            metrics.record_proxy_protocol_dropped(metric_values::PROXY_PROTOCOL_DROP_TIMEOUT);
            warn!(?socket_peer, "PROXY detect timeout");
            return None;
        }
    };

    let read_result = match detection {
        ProxyProtocolDetection::None => {
            return require_drops(
                mode,
                metrics,
                socket_peer,
                metric_values::PROXY_PROTOCOL_DROP_BAD_HEADER,
                "drop: proxy_protocol=require + no PROXY header",
                PassthroughNote::Logged,
            );
        }
        ProxyProtocolDetection::V1 => timeout(timeout_dur, read_proxy_header_v1(stream)).await,
        ProxyProtocolDetection::V2 => timeout(timeout_dur, read_proxy_header_v2(stream)).await,
    };

    peer_from_read_result(read_result, metrics, socket_peer)
}
