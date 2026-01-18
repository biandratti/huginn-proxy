use http::Version;
use hyper::body::Incoming;
use hyper::header::HeaderName;
use hyper::Request;
use opentelemetry::KeyValue;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::debug;

use crate::config::{Backend, KeepAliveConfig, Route};
use crate::fingerprinting::names;
use crate::proxy::forwarding::forward;
use crate::proxy::handler::headers::{add_forwarded_headers, akamai_header_value};
use crate::proxy::handler::rate_limit_validation::check_rate_limit;
use crate::proxy::http_result::{HttpError, HttpResult};
use crate::telemetry::Metrics;
use http::StatusCode;

type RespBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

fn check_ip_access(
    peer: std::net::SocketAddr,
    ip_filter: &crate::config::IpFilterConfig,
    metrics: Option<&Arc<Metrics>>,
) -> HttpResult<()> {
    let client_ip = peer.ip();
    if !crate::security::is_ip_allowed(client_ip, ip_filter) {
        debug!(?peer, "IP blocked by filter");
        if let Some(m) = metrics {
            m.errors_total
                .add(1, &[KeyValue::new("error_type", "ip_blocked")]);
        }
        return Err(HttpError::Forbidden);
    }
    Ok(())
}

/// Handle request routing and forwarding
#[allow(clippy::too_many_arguments)]
pub async fn handle_proxy_request(
    mut req: Request<Incoming>,
    routes: Vec<Route>,
    backends: Arc<Vec<Backend>>,
    tls_header: Option<hyper::header::HeaderValue>,
    fingerprint_rx: Option<watch::Receiver<Option<huginn_net_http::AkamaiFingerprint>>>,
    keep_alive: &KeepAliveConfig,
    security_headers: &crate::config::SecurityHeaders,
    ip_filter: &crate::config::IpFilterConfig,
    rate_limit_config: &crate::config::RateLimitConfig,
    rate_limit_manager: Option<&std::sync::Arc<crate::security::RateLimitManager>>,
    metrics: Option<Arc<Metrics>>,
    peer: std::net::SocketAddr,
    is_https: bool,
) -> HttpResult<hyper::Response<RespBody>> {
    let start = Instant::now();
    let method = req.method().to_string();
    let protocol = format!("{:?}", req.version());

    check_ip_access(peer, ip_filter, metrics.as_ref())?;

    let path = req.uri().path();
    let route_match = if let Some(route) =
        crate::proxy::forwarding::pick_route_with_fingerprinting(path, &routes)
    {
        // Route matched: use route's fingerprinting configuration
        if let Some(ref m) = metrics {
            m.backend_selections_total
                .add(1, &[KeyValue::new("backend", route.backend.to_string())]);
        }
        route
    } else {
        // No route matched: return 404
        let error = HttpError::NoMatchingRoute;
        if let Some(ref m) = metrics {
            m.errors_total
                .add(1, &[KeyValue::new("error_type", error.error_type())]);
        }
        return Err(error);
    };

    if let Some(rate_limited_response) = check_rate_limit(
        rate_limit_manager,
        rate_limit_config,
        &route_match,
        peer,
        req.headers(),
        metrics.as_ref(),
    ) {
        return Ok(rate_limited_response);
    }

    // Extract and inject fingerprints first (fingerprints are extracted from TLS handshake/HTTP2 frames,
    // not from HTTP headers, so adding X-Forwarded-* headers won't affect fingerprint generation)
    if route_match.fingerprinting {
        if let Some(hv) = tls_header {
            req.headers_mut()
                .insert(HeaderName::from_static(names::TLS_JA4), hv);
        }
        if let Some(ref rx) = fingerprint_rx {
            if req.version() == Version::HTTP_2 {
                let akamai = rx.borrow().clone();
                debug!("Handler: akamai fingerprint: {:?}", akamai);
                if let Some(hv) = akamai_header_value(akamai.as_ref()) {
                    debug!("Handler: injecting {} header: {:?}", names::HTTP2_AKAMAI, hv);
                    req.headers_mut()
                        .insert(HeaderName::from_static(names::HTTP2_AKAMAI), hv);
                } else {
                    debug!("Handler: no HTTP fingerprint header to inject (HTTP/2 connection but fingerprint not extracted)");
                    // Record failure metric if metrics available
                    if let Some(ref m) = metrics {
                        m.http2_fingerprint_failures_total.add(1, &[]);
                    }
                }
            } else {
                // HTTP/1.1 connection - Akamai fingerprint not applicable
                debug!("Handler: HTTP/1.1 connection, Akamai fingerprint not applicable");
                if let Some(ref m) = metrics {
                    m.http2_fingerprint_failures_total.add(1, &[]);
                }
            }
        }
    }

    // Add X-Forwarded-* headers after fingerprinting
    // Note: Fingerprints are extracted from TLS handshake/HTTP2 frames (before HTTP request parsing),
    // so adding these headers doesn't affect fingerprint generation
    add_forwarded_headers(&mut req, peer, is_https);

    // Forward request
    let result = forward(
        req,
        route_match.backend.to_string(),
        crate::proxy::forwarding::ForwardConfig {
            backends: &backends,
            keep_alive,
            metrics: metrics.clone(),
            matched_prefix: route_match.matched_prefix,
            replace_path: route_match.replace_path,
            security_headers: Some(security_headers),
            is_https,
        },
    )
    .await;

    let duration = start.elapsed().as_secs_f64();
    let status_code = match &result {
        Ok(resp) => resp.status().as_u16(),
        Err(e) => {
            let code: StatusCode = (*e).clone().into();
            code.as_u16()
        }
    };

    if let Some(ref m) = metrics {
        m.requests_total.add(
            1,
            &[
                KeyValue::new("method", method.clone()),
                KeyValue::new("status_code", status_code.to_string()),
                KeyValue::new("protocol", protocol.clone()),
            ],
        );
        m.requests_duration_seconds.record(
            duration,
            &[
                KeyValue::new("method", method),
                KeyValue::new("status_code", status_code.to_string()),
                KeyValue::new("protocol", protocol),
            ],
        );
    }

    result
}
