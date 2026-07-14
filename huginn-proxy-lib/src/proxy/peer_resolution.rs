use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use tokio::net::TcpStream;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use crate::config::{ProxyProtocolConfig, ProxyProtocolMode};
use crate::proxy::protocol::{
    detect_proxy_protocol, normalize_mapped_ipv4, read_proxy_header_v1, read_proxy_header_v2,
    ProxyProtocolDetection, ProxyProtocolError, ProxySource,
};
use crate::telemetry::values as metric_values;
use crate::telemetry::Metrics;

/// Runtime form of `listen.proxy_protocol`: the mode plus the effective header-read timeout,
/// resolved once in `server::run` rather than on every accepted connection.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedProxyProtocol {
    pub mode: ProxyProtocolMode,
    pub header_timeout: Duration,
}

impl ResolvedProxyProtocol {
    /// Resolve a listener's static [`ProxyProtocolConfig`] into this runtime form.
    pub fn resolve(config: ProxyProtocolConfig) -> Self {
        Self {
            mode: config.mode,
            header_timeout: Duration::from_millis(config.header_timeout_ms),
        }
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
