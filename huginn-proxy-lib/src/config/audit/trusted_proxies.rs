//! Audit for over-broad `security.trusted_proxies` ranges.

use ipnet::IpNet;

use super::ConfigWarning;
use crate::config::Config;

/// An IPv4 `trusted_proxies` prefix shorter than this (i.e. broader than `/8`) is flagged as very
/// broad. Sits just above the largest standard private block (`10.0.0.0/8`), so LAN ranges never warn.
const IPV4_BROAD_PREFIX: u8 = 8;
/// An IPv6 `trusted_proxies` prefix shorter than this (i.e. broader than `/7`) is flagged as very
/// broad. Sits at the ULA boundary (`fc00::/7`), so unique-local/link-local ranges never warn.
const IPV6_BROAD_PREFIX: u8 = 7;

/// Non-fatal audit for over-broad `security.trusted_proxies` entries.
///
/// `trusted_proxies` is the trust boundary for `X-Forwarded-For` (rate-limit client IP) and the
/// PROXY protocol header: a peer inside it is allowed to declare the real client address. An
/// over-broad range therefore lets untrusted clients spoof their source IP, bypassing rate limits,
/// IP filtering, and poisoning logs. Two tiers are reported:
///
/// - **trust-all** (`0.0.0.0/0` or `::/0`, i.e. a `/0` prefix): every peer is trusted, so both XFF
///   and the PROXY header become forgeable by anyone. Reported for either address family, unless
///   `security.trust_all_proxies = true` explicitly opts in (then this tier is suppressed).
/// - **very broad public range**: an IPv4 prefix shorter than `/8` or an IPv6
///   prefix shorter than `/7`. Those thresholds sit just above the standard
///   private/reserved blocks (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`, `fe80::/10`), so
///   ordinary private ranges never warn.
pub fn trusted_proxies_warnings(cfg: &Config) -> Vec<ConfigWarning> {
    let mut out = Vec::new();
    for net in &cfg.security.trusted_proxies {
        if net.prefix_len() == 0 {
            if !cfg.security.trust_all_proxies {
                out.push(ConfigWarning {
                    scope: "trusted_proxies".to_string(),
                    message: format!(
                        "'{net}' trusts every IP address; any client can spoof X-Forwarded-For and the PROXY protocol header"
                    ),
                });
            }
            continue;
        }
        let broad = match net {
            IpNet::V4(_) => net.prefix_len() < IPV4_BROAD_PREFIX,
            IpNet::V6(_) => net.prefix_len() < IPV6_BROAD_PREFIX,
        };
        if broad {
            out.push(ConfigWarning {
                scope: "trusted_proxies".to_string(),
                message: format!(
                    "'{net}' trusts a very large address range; confirm it matches your proxy topology, since trusted peers may set X-Forwarded-For and the PROXY protocol header"
                ),
            });
        }
    }
    out
}
