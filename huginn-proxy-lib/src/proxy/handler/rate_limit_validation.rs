use http::StatusCode;
use hyper::Response;
use ipnet::IpNet;
use std::sync::Arc;
use tracing::debug;

use crate::config::RateLimitConfig;
use crate::proxy::router::RouteMatch;
use crate::security::{extract_rate_limit_key, RateLimitManager, RateLimitResult};
use crate::telemetry::Metrics;
use crate::utils::http::{json_error, RespBody};

/// Check rate limiting for incoming request.
///
/// Returns:
/// - `None` if request is allowed to proceed
/// - `Some(429 response)` if request exceeds rate limit
#[allow(clippy::too_many_arguments)]
pub fn check_rate_limit(
    rate_limit_manager: Option<&Arc<RateLimitManager>>,
    rate_limit_config: &RateLimitConfig,
    route_match: &RouteMatch,
    peer: std::net::SocketAddr,
    headers: &http::HeaderMap,
    metrics: &Arc<Metrics>,
    domain: &str,
    trusted_proxies: &[IpNet],
) -> Option<Response<RespBody>> {
    let manager = rate_limit_manager?;

    // Whole-block replace: when the route carries its own rate-limit block it fully replaces the
    // domain-effective config (key strategy, header); otherwise use that config. `trusted_proxies`
    // is global (not per-scope) and resolves the real client IP from XFF for ip/combined keys.
    let effective = route_match.rate_limit.unwrap_or(rate_limit_config);
    let limit_by = effective.limit_by;
    let limit_by_header = effective.limit_by_header.as_deref();

    let rate_limit_key = extract_rate_limit_key(
        limit_by,
        peer,
        route_match.matched_prefix,
        limit_by_header,
        headers,
        trusted_proxies,
    );

    let strategy = format!("{:?}", limit_by).to_lowercase();
    metrics.record_rate_limit_request(&strategy, route_match.matched_prefix, domain);

    let rate_limit_result =
        manager.check(&rate_limit_key, domain, Some(route_match.matched_prefix));

    match rate_limit_result {
        RateLimitResult::Limited { limit, reset_after, .. } => {
            metrics.record_rate_limit_rejection(&strategy, route_match.matched_prefix, domain);
            Some(create_429_response(limit, reset_after.as_secs()))
        }
        RateLimitResult::Allowed { limit, remaining } => {
            debug!(limit = limit, remaining = remaining, "Rate limit check passed");
            metrics.record_rate_limit_allowed(&strategy, route_match.matched_prefix, domain);
            None
        }
    }
}

fn create_429_response(limit: isize, reset_after_secs: u64) -> Response<RespBody> {
    let mut resp = json_error(StatusCode::TOO_MANY_REQUESTS, "too_many_requests");

    resp.headers_mut().insert(
        hyper::header::HeaderName::from_static("x-rate-limit-limit"),
        hyper::header::HeaderValue::from_str(&limit.to_string())
            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("0")),
    );
    resp.headers_mut().insert(
        hyper::header::HeaderName::from_static("x-rate-limit-remaining"),
        hyper::header::HeaderValue::from_static("0"),
    );
    resp.headers_mut().insert(
        hyper::header::HeaderName::from_static("x-ratelimit-reset"),
        hyper::header::HeaderValue::from_str(&reset_after_secs.to_string())
            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("0")),
    );

    resp
}
