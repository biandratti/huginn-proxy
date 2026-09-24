use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::{ProxyError, Result};

/// PROXY protocol (v1 and v2) handling for a listener.
///
/// Honored **only** for peers in `security.trusted_proxies` (anti-spoofing). v1 and v2 are
/// auto-detected; neither signature collides with a TLS ClientHello or HTTP, so `Optional` lets
/// one config work whether or not huginn sits behind an L4 proxy.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    /// Never read a PROXY header; `peer` is the socket peer (today's behavior).
    #[default]
    Off,
    /// Auto-detect: if a trusted peer sends a PROXY header (v1 or v2), use it; otherwise use the
    /// socket peer. One config works behind a proxy or directly.
    Optional,
    /// A trusted peer MUST send a valid PROXY header; otherwise the connection is dropped.
    Require,
}

/// PROXY protocol configuration for a listener: whether/how to honor it, and how long to wait
/// for the header. Both settings are static (restart to apply) - `mode` alters the socket
/// handshake, and `header_timeout_ms` is resolved at config parse time (`<= 0` maps to 1 s).
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyProtocolConfig {
    /// PROXY protocol handling. Only honored from peers in `security.trusted_proxies`.
    /// Default: off.
    #[serde(default)]
    pub mode: ProxyProtocolMode,
    /// Timeout to read a PROXY header (v1 or v2) after a trusted peer is detected, in
    /// milliseconds. Covers both the version-sniff peek loop and the full header read.
    /// Legitimate L4 proxies send a small header (v1 ≤107 B, v2 typically ~28 B) at connection
    /// start, so the default 100 ms timeout is well below the TLS handshake timeout.
    /// `<= 0` is resolved at config parse time to a 1 s internal fallback (not recommended: a
    /// slow/hostile trusted peer could park a connection slot for that long). Only relevant when
    /// `mode` is `optional` or `require`. Default: 100.
    #[serde(default = "default_proxy_protocol_header_timeout_ms")]
    #[serde(deserialize_with = "deserialize_proxy_protocol_header_timeout_ms")]
    pub header_timeout_ms: u64,
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        Self {
            mode: ProxyProtocolMode::Off,
            header_timeout_ms: default_proxy_protocol_header_timeout_ms(),
        }
    }
}

const DEFAULT_LISTEN_ADDRESS_V4: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
const DEFAULT_LISTEN_ADDRESS_V6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

/// Listener configuration: ports, bind addresses, and kernel socket options.
///
/// Sockets are built like rust-rpxy `build_listen_sockets`: each IP combined with each
/// present port. There is no `addrs` (`host:port`) list.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// Plain HTTP port. Absent: no HTTP sockets.
    #[serde(default)]
    pub port: Option<u16>,
    /// HTTPS port. Absent: no TLS sockets.
    #[serde(default)]
    pub port_tls: Option<u16>,
    /// Bind IPv6 `::` in addition to IPv4 when `address_v6` is omitted. Default: false.
    #[serde(default)]
    pub ipv6: bool,
    /// IPv4 bind addresses. Absent: `0.0.0.0`. Must not be empty; must not mix `0.0.0.0` with
    /// other addresses.
    #[serde(default)]
    pub address_v4: Option<Vec<String>>,
    /// IPv6 bind addresses. Absent: `::` only when `ipv6` is true. Must not be empty; must not
    /// mix `::` with other addresses. Bracketed (`[::1]`) and bare (`::1`) forms are accepted.
    #[serde(default)]
    pub address_v6: Option<Vec<String>>,
    /// `listen(2)` backlog, length of the pending-connection queue per listener socket.
    /// Raise this under high connection rates to avoid the kernel silently dropping SYNs before
    /// `accept(2)` is called. The kernel clamps the value to `net.core.somaxconn`.
    /// Passed directly to `listen(2)`. Default: 4096 (matches modern Linux SOMAXCONN)
    #[serde(default = "default_tcp_backlog")]
    pub tcp_backlog: i32,
    /// PROXY protocol (v1 and v2) handling: mode and header read timeout. See
    /// [`ProxyProtocolConfig`].
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            port: None,
            port_tls: None,
            ipv6: false,
            address_v4: None,
            address_v6: None,
            tcp_backlog: default_tcp_backlog(),
            proxy_protocol: ProxyProtocolConfig::default(),
        }
    }
}

fn default_tcp_backlog() -> i32 {
    4096
}

fn default_proxy_protocol_header_timeout_ms() -> u64 {
    100
}

/// Fallback when `listen.proxy_protocol.header_timeout_ms` is configured as `<= 0` (1 s).
const PROXY_PROTOCOL_HEADER_TIMEOUT_FALLBACK_MS: u64 = 1000;

/// Resolve `listen.proxy_protocol.header_timeout_ms`, mapping `<= 0` to
/// [`PROXY_PROTOCOL_HEADER_TIMEOUT_FALLBACK_MS`]. Called from config deserialization.
fn resolve_proxy_protocol_header_timeout_ms(configured_ms: i64) -> u64 {
    if configured_ms <= 0 {
        warn!(
            "listen.proxy_protocol.header_timeout_ms={configured_ms}: falling back to {} ms. This \
             is not recommended - a slow or hostile trusted peer can hold a connection slot for \
             that long while withholding the PROXY header.",
            PROXY_PROTOCOL_HEADER_TIMEOUT_FALLBACK_MS
        );
        PROXY_PROTOCOL_HEADER_TIMEOUT_FALLBACK_MS
    } else {
        configured_ms as u64
    }
}

fn deserialize_proxy_protocol_header_timeout_ms<'de, D>(
    deserializer: D,
) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ms = i64::deserialize(deserializer)?;
    Ok(resolve_proxy_protocol_header_timeout_ms(ms))
}

/// Allowlisted effective-config view of [`ListenConfig`]. Field names are the JSON keys.
#[derive(Serialize)]
pub(crate) struct ListenView {
    port: Option<u16>,
    port_tls: Option<u16>,
    ipv6: bool,
    address_v4: Option<Vec<String>>,
    address_v6: Option<Vec<String>>,
    tcp_backlog: i32,
    proxy_protocol: ProxyProtocolView,
}

#[derive(Serialize)]
struct ProxyProtocolView {
    mode: &'static str,
    header_timeout_ms: u64,
}

impl ListenConfig {
    /// HTTP on `127.0.0.1` at `port`. Used by tests and benches that bind a concrete port.
    pub fn localhost_http(port: u16) -> Self {
        Self {
            port: Some(port),
            address_v4: Some(vec!["127.0.0.1".to_string()]),
            ..Default::default()
        }
    }

    /// HTTPS on `127.0.0.1` at `port`. Used by tests and benches that terminate TLS.
    pub fn localhost_https(port: u16) -> Self {
        Self {
            port_tls: Some(port),
            address_v4: Some(vec!["127.0.0.1".to_string()]),
            ..Default::default()
        }
    }

    pub(crate) fn effective_view(&self) -> ListenView {
        ListenView {
            port: self.port,
            port_tls: self.port_tls,
            ipv6: self.ipv6,
            address_v4: self.address_v4.clone(),
            address_v6: self.address_v6.clone(),
            tcp_backlog: self.tcp_backlog,
            proxy_protocol: ProxyProtocolView {
                mode: self.proxy_protocol.mode.as_str(),
                header_timeout_ms: self.proxy_protocol.header_timeout_ms,
            },
        }
    }

    /// Validate ports and addresses, then return the sockets to bind.
    ///
    /// `tls_enabled` is stamped here from the config field that produced the
    /// socket (`port` vs `port_tls`), before `bind`.
    pub fn sockets(&self) -> Result<Vec<ListenSocket>> {
        self.validate_ports()?;
        build_listen_sockets(
            &self.address_v4,
            &self.address_v6,
            self.ipv6,
            self.port,
            self.port_tls,
        )
    }

    fn validate_ports(&self) -> Result<()> {
        if self.port.is_none() && self.port_tls.is_none() {
            return Err(ProxyError::Config(
                "Either or both of listen.port and listen.port_tls must be specified".to_string(),
            ));
        }
        if let (Some(http), Some(https)) = (self.port, self.port_tls)
            && http == https
        {
            return Err(ProxyError::Config(
                "listen.port and listen.port_tls must be different".to_string(),
            ));
        }
        Ok(())
    }
}

/// One bind target: address plus whether this socket was created from `port_tls`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenSocket {
    pub addr: SocketAddr,
    pub tls_enabled: bool,
}

/// Validate and combine listen addresses with ports. Mirrors rust-rpxy `build_listen_sockets`.
fn build_listen_sockets(
    listen_addresses_v4: &Option<Vec<String>>,
    listen_addresses_v6: &Option<Vec<String>>,
    listen_ipv6: bool,
    http_port: Option<u16>,
    https_port: Option<u16>,
) -> Result<Vec<ListenSocket>> {
    let mut listen_ips: Vec<IpAddr> = Vec::new();

    if let Some(addrs) = listen_addresses_v4 {
        if addrs.is_empty() {
            return Err(ProxyError::Config(
                "listen.address_v4 must not be an empty array".to_string(),
            ));
        }
        let listen_v4_ips = addrs
            .iter()
            .map(|addr_str| {
                addr_str.parse::<Ipv4Addr>().map_err(|e| {
                    ProxyError::Config(format!("Invalid listen.address_v4 '{addr_str}': {e}"))
                })
            })
            .collect::<Result<HashSet<_>>>()?;
        if listen_v4_ips.len() > 1 && listen_v4_ips.iter().any(Ipv4Addr::is_unspecified) {
            return Err(ProxyError::Config(
                "listen.address_v4 must not contain the wildcard address '0.0.0.0' when \
                 multiple addresses are specified"
                    .to_string(),
            ));
        }
        listen_ips.extend(listen_v4_ips.into_iter().map(IpAddr::V4));
    } else {
        listen_ips.push(IpAddr::V4(DEFAULT_LISTEN_ADDRESS_V4));
    }

    if let Some(addrs) = listen_addresses_v6 {
        if addrs.is_empty() {
            return Err(ProxyError::Config(
                "listen.address_v6 must not be an empty array".to_string(),
            ));
        }
        let listen_v6_ips = addrs
            .iter()
            .map(|addr_str| {
                let stripped = addr_str
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .unwrap_or(addr_str);
                stripped.parse::<Ipv6Addr>().map_err(|e| {
                    ProxyError::Config(format!("Invalid listen.address_v6 '{addr_str}': {e}"))
                })
            })
            .collect::<Result<HashSet<_>>>()?;
        if listen_v6_ips.len() > 1 && listen_v6_ips.iter().any(Ipv6Addr::is_unspecified) {
            return Err(ProxyError::Config(
                "listen.address_v6 must not contain the wildcard address '::' when \
                 multiple addresses are specified"
                    .to_string(),
            ));
        }
        listen_ips.extend(listen_v6_ips.into_iter().map(IpAddr::V6));
    } else if listen_ipv6 {
        listen_ips.push(IpAddr::V6(DEFAULT_LISTEN_ADDRESS_V6));
    }

    let sockets = listen_ips
        .iter()
        .flat_map(|ip| {
            let mut v = Vec::new();
            if let Some(port) = http_port {
                v.push(ListenSocket { addr: SocketAddr::new(*ip, port), tls_enabled: false });
            }
            if let Some(port) = https_port {
                v.push(ListenSocket { addr: SocketAddr::new(*ip, port), tls_enabled: true });
            }
            v
        })
        .collect();

    Ok(sockets)
}

impl ProxyProtocolMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ProxyProtocolMode::Off => "off",
            ProxyProtocolMode::Optional => "optional",
            ProxyProtocolMode::Require => "require",
        }
    }
}
