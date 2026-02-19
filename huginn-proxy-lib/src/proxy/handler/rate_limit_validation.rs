use http::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::Response;
use std::sync::Arc;
use tracing::debug;

use crate::config::RateLimitConfig;
use crate::proxy::forwarding::RouteMatch;
use crate::security::{extract_rate_limit_key, RateLimitManager, RateLimitResult};
use crate::telemetry::Metrics;

type RespBody = BoxBody<bytes::Bytes, hyper::Error>;

/// Check rate limiting for incoming request.
///
/// Returns:
/// - `None` if request is allowed to proceed
/// - `Some(429 response)` if request exceeds rate limit
pub fn check_rate_limit(
    rate_limit_manager: Option<&Arc<RateLimitManager>>,
    rate_limit_config: &RateLimitConfig,
    route_match: &RouteMatch,
    peer: std::net::SocketAddr,
    headers: &http::HeaderMap,
    metrics: Option<&Arc<Metrics>>,
) -> Option<Response<RespBody>> {
    let manager = rate_limit_manager?;

    let limit_by = route_match
        .rate_limit
        .as_ref()
        .and_then(|rl| rl.limit_by)
        .unwrap_or(rate_limit_config.limit_by);

    let limit_by_header = route_match
        .rate_limit
        .as_ref()
        .and_then(|rl| rl.limit_by_header.as_deref())
        .or(rate_limit_config.limit_by_header.as_deref());

    let rate_limit_key = extract_rate_limit_key(
        limit_by,
        peer,
        route_match.matched_prefix,
        limit_by_header,
        headers,
    );

    let strategy = format!("{:?}", limit_by).to_lowercase();
    if let Some(m) = metrics {
        m.record_rate_limit_request(&strategy, route_match.matched_prefix);
    }

    let rate_limit_result = manager.check(&rate_limit_key, Some(route_match.matched_prefix));

    match rate_limit_result {
        RateLimitResult::Limited { limit, reset_after, .. } => {
            if let Some(m) = metrics {
                m.record_rate_limit_rejection(&strategy, route_match.matched_prefix);
            }

            Some(create_429_response(limit, reset_after.as_secs()))
        }
        RateLimitResult::Allowed { limit, remaining } => {
            debug!(limit = limit, remaining = remaining, "Rate limit check passed");

            if let Some(m) = metrics {
                m.record_rate_limit_allowed(&strategy, route_match.matched_prefix);
            }

            None
        }
    }
}

fn create_429_response(limit: isize, reset_after_secs: u64) -> Response<RespBody> {
    let body = Full::new(bytes::Bytes::from("Too Many Requests"))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;

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
