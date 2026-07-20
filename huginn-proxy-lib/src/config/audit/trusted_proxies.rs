//! Audit for over-broad `security.trusted_proxies` ranges.

use ipnet::IpNet;

use super::ConfigWarning;
use crate::config::Config;

/// An IPv4 `trusted_proxies` prefix shorter than this (i.e. broader than `/8`) is flagged as very
/// broad. The threshold sits at the largest standard private block, `10.0.0.0/8` (RFC 1918), which
/// is the widest range a legitimate LAN deployment would list; the other private/reserved blocks
/// (`172.16.0.0/12`, `192.168.0.0/16` — RFC 1918; `100.64.0.0/10` — RFC 6598 CGNAT) are all
/// narrower, so ordinary private ranges never warn while genuinely public ranges do. Heuristic (not
/// a spec-mandated value); tune here to change strictness.
const IPV4_BROAD_PREFIX: u8 = 8;
/// An IPv6 `trusted_proxies` prefix shorter than this (i.e. broader than `/7`) is flagged as very
/// broad. The threshold sits at the ULA block `fc00::/7` (RFC 4193), the widest "private" IPv6 range;
/// link-local `fe80::/10` is narrower, so unique-local/link-local ranges never warn. Heuristic (not a
/// spec-mandated value); tune here to change strictness.
const IPV6_BROAD_PREFIX: u8 = 7;

/// Non-fatal audit for over-broad `security.trusted_proxies` entries.
///
/// `trusted_proxies` is the trust boundary for `X-Forwarded-For` (rate-limit client IP) and the
/// PROXY protocol header: a peer inside it is allowed to declare the real client address. An
/// over-broad range therefore lets untrusted clients spoof their source IP, bypassing rate limits,
/// IP filtering, and poisoning logs. Two tiers are reported:
///
/// - **trust-all** (`0.0.0.0/0` or `::/0`, i.e. a `/0` prefix in `cidrs`): every peer is trusted, so
///   both XFF and the PROXY header become forgeable by anyone. Reported for either address family,
///   unless `security.trusted_proxies.insecure = true` explicitly opts in (then this tier is
///   suppressed, since `insecure` already trusts every peer by design).
/// - **very broad public range**: an IPv4 prefix shorter than `/8` or an IPv6 prefix shorter than
///   `/7`. Those thresholds sit at the standard private/reserved blocks — `10/8`, `172.16/12`,
///   `192.168/16` (RFC 1918), `fc00::/7` (RFC 4193 ULA), `fe80::/10` (link-local) — so ordinary
///   private ranges never warn. See the `IPV4_BROAD_PREFIX` / `IPV6_BROAD_PREFIX` consts for the
///   rationale. These are heuristic thresholds, not spec-mandated values.
pub fn trusted_proxies_warnings(cfg: &Config) -> Vec<ConfigWarning> {
    let trusted_proxies = &cfg.security.trusted_proxies;
    let mut out = Vec::new();
    for net in &trusted_proxies.cidrs {
        if net.prefix_len() == 0 {
            if !trusted_proxies.insecure {
                out.push(ConfigWarning {
                    scope: "trusted_proxies".to_string(),
                    message: format!(
                        "'{net}' trusts every IP address; set security.trusted_proxies.insecure = true to acknowledge, or narrow the range (any client can otherwise spoof X-Forwarded-For and the PROXY protocol header)"
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
