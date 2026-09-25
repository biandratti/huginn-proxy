use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{ProxyError, Result};

const DEFAULT_LISTEN_ADDRESS_V4: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
const DEFAULT_LISTEN_ADDRESS_V6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

/// One bind target produced from [`super::ListenConfig`]: address plus whether TLS is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenSocket {
    pub addr: SocketAddr,
    pub tls_enabled: bool,
}

/// Validate and combine listen addresses with ports.
pub(super) fn build_listen_sockets(
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
