use super::{RateLimitResult, RateLimiter};
use crate::config::{Domain, LimitBy, RateLimitConfig};
use ahash::AHashMap;
use ipnet::IpNet;
use std::net::IpAddr;
use std::time::Duration;

/// Manager for rate limiters (global and per-route).
///
/// This struct holds rate limiters for:
/// - Global rate limiting (applies to all routes unless overridden).
/// - Per-route rate limiting (specific limits for individual routes).
///
/// The manager is immutable after construction. Hot reload swaps the entire
/// manager atomically via `proxy::reload::SharedRateLimiter`
pub struct RateLimitManager {
    /// Global rate limiter (optional)
    global: Option<RateLimiter>,
    /// Per-route rate limiters
    route_limiters: AHashMap<String, RateLimiter>,
}

impl RateLimitManager {
    /// Create a new rate limit manager from configuration.
    ///
    /// Iterates all routes across all domains to build per-route limiters.
    pub fn new(global_config: &RateLimitConfig, domains: &[Domain]) -> Self {
        let global = if global_config.enabled {
            let window = Duration::from_secs(global_config.window_seconds);
            Some(RateLimiter::new(global_config.requests_per_second, global_config.burst, window))
        } else {
            None
        };

        let mut route_limiters = AHashMap::new();
        for route in domains.iter().flat_map(|d| d.routes.iter()) {
            if let Some(ref rl) = route.rate_limit {
                let enabled = rl.enabled.unwrap_or(global_config.enabled);
                if enabled {
                    let rps = rl
                        .requests_per_second
                        .unwrap_or(global_config.requests_per_second);
                    let burst = rl.burst.unwrap_or(global_config.burst);
                    let window = Duration::from_secs(
                        rl.window_seconds.unwrap_or(global_config.window_seconds),
                    );
                    route_limiters
                        .insert(route.prefix.clone(), RateLimiter::new(rps, burst, window));
                }
            }
        }

        Self { global, route_limiters }
    }

    /// Check if a request is allowed (not rate limited)
    ///
    /// # Arguments
    /// * `key` - Rate limiting key (IP, header value, route, or combination)
    /// * `route_prefix` - Matched route prefix (for per-route limiting)
    ///
    /// # Returns
    /// * `RateLimitResult::Allowed` if request is permitted
    /// * `RateLimitResult::Limited` if request exceeds rate limit
    pub fn check(&self, key: &str, route_prefix: Option<&str>) -> RateLimitResult {
        if let Some(prefix) = route_prefix {
            if let Some(limiter) = self.route_limiters.get(prefix) {
                return limiter.check(key);
            }
        }

        match &self.global {
            Some(global_limiter) => global_limiter.check(key),
            None => RateLimitResult::Allowed { remaining: isize::MAX, limit: isize::MAX },
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.global.is_some() || !self.route_limiters.is_empty()
    }
}

/// Resolve the effective client IP for rate limiting.
///
/// When `trusted_proxies` is empty, returns the TCP peer IP unconditionally,
/// this is the secure default and cannot be spoofed by a client.
///
/// When `trusted_proxies` is non-empty and the peer itself is a trusted proxy,
/// walks `X-Forwarded-For` right-to-left (our proxy appends the peer IP, so the
/// rightmost entry is the most recently added and most trustworthy) and returns
/// the first IP that it is NOT in the trusted set. Falls back to the peer IP if all
/// XFF entries are trusted or the header is absent/malformed.
fn resolve_client_ip(
    peer: std::net::SocketAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &[IpNet],
) -> String {
    let peer_ip = peer.ip();
    if trusted_proxies.is_empty() || !trusted_proxies.iter().any(|net| net.contains(&peer_ip)) {
        return peer_ip.to_string();
    }
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            for raw in xff_str.rsplit(',') {
                if let Ok(ip) = raw.trim().parse::<IpAddr>() {
                    if !trusted_proxies.iter().any(|net| net.contains(&ip)) {
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
    trusted_proxies: &[IpNet],
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
