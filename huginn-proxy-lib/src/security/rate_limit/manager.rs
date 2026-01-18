use ahash::AHashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use super::{RateLimitResult, RateLimiter};
use crate::config::{LimitBy, RateLimitConfig, Route};

/// Manager for rate limiters (global and per-route)
///
/// This struct holds rate limiters for:
/// - Global rate limiting (applies to all routes unless overridden)
/// - Per-route rate limiting (specific limits for individual routes)
///
pub struct RateLimitManager {
    /// Global rate limiter (optional)
    global: Option<Arc<RateLimiter>>,
    /// Per-route rate limiters
    route_limiters: Arc<RwLock<AHashMap<String, Arc<RateLimiter>>>>,
}

impl RateLimitManager {
    /// Create a new rate limit manager from configuration
    ///
    /// # Arguments
    /// * `global_config` - Global rate limiting configuration
    /// * `routes` - Route configurations (with optional per-route rate limits)
    pub fn new(global_config: &RateLimitConfig, routes: &[Route]) -> Self {
        let global = if global_config.enabled {
            let window = Duration::from_secs(global_config.window_seconds);
            Some(Arc::new(RateLimiter::new(
                global_config.requests_per_second,
                global_config.burst,
                window,
            )))
        } else {
            None
        };

        let mut route_limiters = AHashMap::new();
        for route in routes {
            if let Some(ref route_rate_limit) = route.rate_limit {
                let enabled = route_rate_limit.enabled.unwrap_or(global_config.enabled);
                if enabled {
                    let rps = route_rate_limit
                        .requests_per_second
                        .unwrap_or(global_config.requests_per_second);
                    let burst = route_rate_limit.burst.unwrap_or(global_config.burst);
                    let window = Duration::from_secs(global_config.window_seconds);

                    let limiter = Arc::new(RateLimiter::new(rps, burst, window));
                    route_limiters.insert(route.prefix.clone(), limiter);
                }
            }
        }

        Self { global, route_limiters: Arc::new(RwLock::new(route_limiters)) }
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
        // Check per-route limiter first (if exists)
        if let Some(prefix) = route_prefix {
            let limiters = match self.route_limiters.read() {
                Ok(guard) => guard,
                Err(_) => {
                    tracing::warn!("Rate limit manager lock poisoned");
                    return RateLimitResult::Allowed { remaining: 0, limit: 0 };
                }
            };

            if let Some(limiter) = limiters.get(prefix) {
                return limiter.check(key);
            }
        }

        if let Some(ref global_limiter) = self.global {
            return global_limiter.check(key);
        }

        RateLimitResult::Allowed { remaining: isize::MAX, limit: isize::MAX }
    }

    pub fn is_enabled(&self) -> bool {
        self.global.is_some() || {
            match self.route_limiters.read() {
                Ok(guard) => !guard.is_empty(),
                Err(_) => false,
            }
        }
    }
}

/// Extract rate limiting key from request context
///
/// # Arguments
/// * `limit_by` - Key extraction strategy
/// * `peer` - Client socket address
/// * `route_prefix` - Matched route prefix
/// * `header_name` - Custom header name (for `LimitBy::Header`)
/// * `headers` - HTTP request headers
///
/// # Returns
/// Rate limiting key as a string
pub fn extract_rate_limit_key(
    limit_by: LimitBy,
    peer: std::net::SocketAddr,
    route_prefix: &str,
    header_name: Option<&str>,
    headers: &http::HeaderMap,
) -> String {
    match limit_by {
        LimitBy::Ip => {
            if let Some(xff) = headers.get("x-forwarded-for") {
                if let Ok(xff_str) = xff.to_str() {
                    if let Some(first_ip) = xff_str.split(',').next() {
                        return first_ip.trim().to_string();
                    }
                }
            }
            // Fall back to peer IP
            peer.ip().to_string()
        }
        LimitBy::Header => {
            if let Some(name) = header_name {
                if let Some(value) = headers.get(name) {
                    if let Ok(value_str) = value.to_str() {
                        return value_str.to_string();
                    }
                }
            }
            // Fall back to IP if header not found
            peer.ip().to_string()
        }
        LimitBy::Route => {
            // Use route prefix as key (all clients share same limit)
            route_prefix.to_string()
        }
        LimitBy::Combined => {
            // Combine IP and route for per-IP, per-route limiting
            let ip_str = if let Some(xff) = headers.get("x-forwarded-for") {
                xff.to_str()
                    .ok()
                    .and_then(|s| s.split(',').next())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| peer.ip().to_string())
            } else {
                peer.ip().to_string()
            };
            format!("{ip_str}:{route_prefix}")
        }
    }
}
