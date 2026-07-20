use super::{RateLimitResult, RateLimiter};
use crate::config::{Domain, LimitBy, RateLimitConfig, TrustedProxiesConfig};
use ahash::AHashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Build the limiter for a fully-resolved config (`None` when disabled).
fn build_limiter(config: &RateLimitConfig) -> Option<RateLimiter> {
    if config.enabled {
        let window = Duration::from_secs(config.window_seconds);
        Some(RateLimiter::new(config.requests_per_second, config.burst, window))
    } else {
        None
    }
}

/// Manager for rate limiters (global, per-domain, and per-route).
///
/// This struct holds rate limiters for:
/// - Global rate limiting (applies to every domain unless overridden).
/// - Per-domain rate limiting (`[domains.security.rate_limit]`, whole-block replace).
/// - Per-route rate limiting (`[domains.routes.security.rate_limit]`, whole-block replace).
///
/// Limiters are keyed by domain label so the same route prefix under two different
/// domains stays isolated. The manager is immutable after construction. Hot reload
/// swaps the entire manager atomically via `proxy::reload::SharedRateLimiter`.
pub struct RateLimitManager {
    /// Global rate limiter (optional)
    global: Option<RateLimiter>,
    /// Per-domain limiters keyed by domain label. Present only when the domain overrides
    /// rate limiting: `Some` = enabled limiter, `None` = explicitly disabled (does NOT fall
    /// through to the global limiter). Domains without an override are absent from the map.
    domain_limiters: AHashMap<String, Option<RateLimiter>>,
    /// Per-route limiters: domain label -> route prefix -> slot. Present only when the route
    /// overrides rate limiting: `Some` = enabled limiter, `None` = explicitly disabled (does NOT
    /// fall through to the domain/global limiter). Routes without an override are absent from the map.
    route_limiters: AHashMap<String, AHashMap<String, Option<RateLimiter>>>,
}

impl RateLimitManager {
    /// Create a new rate limit manager from configuration.
    ///
    /// Whole-block replace at every scope: a domain `rate_limit` override fully replaces the
    /// global policy for that domain, and a route override fully replaces it for that route.
    /// Each present override is recorded as an explicit slot (enabled limiter or explicit
    /// disable) so it never silently inherits the level it replaced.
    pub fn new(global_config: &RateLimitConfig, domains: &[Domain]) -> Self {
        let global = build_limiter(global_config);

        let mut domain_limiters = AHashMap::new();
        let mut route_limiters: AHashMap<String, AHashMap<String, Option<RateLimiter>>> =
            AHashMap::new();

        for domain in domains {
            let label = domain.label().to_string();
            let domain_override = domain.security.as_ref().and_then(|s| s.rate_limit.as_ref());

            // Record an explicit domain slot only when the domain overrides rate limiting, so a
            // disabled override (`enabled = false`) does not fall through to the global limiter.
            if let Some(cfg) = domain_override {
                domain_limiters.insert(label.clone(), build_limiter(cfg));
            }

            for route in &domain.routes {
                if let Some(cfg) = route.security.as_ref().and_then(|s| s.rate_limit.as_ref()) {
                    route_limiters
                        .entry(label.clone())
                        .or_default()
                        .insert(route.prefix.clone(), build_limiter(cfg));
                }
            }
        }

        Self { global, domain_limiters, route_limiters }
    }

    /// Check if a request is allowed (not rate limited)
    ///
    /// Precedence: route limiter (for `domain_label` + `route_prefix`) → domain override
    /// (enabled or explicitly disabled) → global limiter.
    ///
    /// # Arguments
    /// * `key` - Rate limiting key (IP, header value, route, or combination)
    /// * `domain_label` - Matched domain label (for per-domain / per-route limiting)
    /// * `route_prefix` - Matched route prefix (for per-route limiting)
    ///
    /// # Returns
    /// * `RateLimitResult::Allowed` if request is permitted
    /// * `RateLimitResult::Limited` if request exceeds rate limit
    pub fn check(
        &self,
        key: &str,
        domain_label: &str,
        route_prefix: Option<&str>,
    ) -> RateLimitResult {
        // A route-level override is authoritative: an enabled limiter is checked, an explicit
        // disable allows the request, and neither falls through to the domain/global limiter.
        if let Some(prefix) = route_prefix {
            if let Some(by_prefix) = self.route_limiters.get(domain_label) {
                if let Some(slot) = by_prefix.get(prefix) {
                    return match slot {
                        Some(limiter) => limiter.check(key),
                        None => {
                            RateLimitResult::Allowed { remaining: isize::MAX, limit: isize::MAX }
                        }
                    };
                }
            }
        }

        // A domain-level override is authoritative: an enabled limiter is checked, an explicit
        // disable allows the request, and neither falls through to the global limiter.
        if let Some(slot) = self.domain_limiters.get(domain_label) {
            return match slot {
                Some(limiter) => limiter.check(key),
                None => RateLimitResult::Allowed { remaining: isize::MAX, limit: isize::MAX },
            };
        }

        match &self.global {
            Some(global_limiter) => global_limiter.check(key),
            None => RateLimitResult::Allowed { remaining: isize::MAX, limit: isize::MAX },
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.global.is_some()
            || self.domain_limiters.values().any(Option::is_some)
            || self
                .route_limiters
                .values()
                .any(|m| m.values().any(Option::is_some))
    }
}

/// Resolve the effective client IP for rate limiting.
///
/// When no peer is trusted (empty `cidrs` and not `insecure`), returns the TCP peer IP
/// unconditionally, this is the secure default and cannot be spoofed by a client.
///
/// When the peer is a trusted proxy, walks the inbound `X-Forwarded-For` right-to-left
/// (most-trusted first) and returns the first non-trusted IP, the real client behind
/// the load balancer. Falls back to the peer IP if all entries are trusted or absent.
fn resolve_client_ip(
    peer: std::net::SocketAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &TrustedProxiesConfig,
) -> String {
    let peer_ip = peer.ip();
    if !trusted_proxies.trusts(&peer_ip) {
        return peer_ip.to_string();
    }
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            for raw in xff_str.rsplit(',') {
                if let Ok(ip) = raw.trim().parse::<IpAddr>() {
                    if !trusted_proxies.trusts(&ip) {
                        return ip.to_string();
                    }
                }
            }
        }
    }
    peer_ip.to_string()
}

/// Extract rate limiting key from request context.
///
/// # Arguments
/// * `limit_by` - Key extraction strategy
/// * `peer` - Client socket address (TCP peer, non-forgeable)
/// * `route_prefix` - Matched route prefix
/// * `header_name` - Custom header name (for `LimitBy::Header`)
/// * `headers` - HTTP request headers
/// * `trusted_proxies` - CIDRs whose XFF additions are trusted (see `resolve_client_ip`)
///
/// # Returns
/// Rate limiting key as a string
pub fn extract_rate_limit_key(
    limit_by: LimitBy,
    peer: std::net::SocketAddr,
    route_prefix: &str,
    header_name: Option<&str>,
    headers: &http::HeaderMap,
    trusted_proxies: &TrustedProxiesConfig,
) -> String {
    match limit_by {
        LimitBy::Ip => resolve_client_ip(peer, headers, trusted_proxies),
        LimitBy::Header => {
            if let Some(name) = header_name {
                if let Some(value) = headers.get(name) {
                    if let Ok(value_str) = value.to_str() {
                        return value_str.to_string();
                    }
                }
            }
            peer.ip().to_string()
        }
        LimitBy::Route => route_prefix.to_string(),
        LimitBy::Combined => {
            let ip_str = resolve_client_ip(peer, headers, trusted_proxies);
            format!("{ip_str}:{route_prefix}")
        }
    }
}
