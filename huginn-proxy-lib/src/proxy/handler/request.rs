use http::Version;
use hyper::body::Incoming;
use hyper::header::HeaderName;
use hyper::Request;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::debug;

use crate::config::{Backend, KeepAliveConfig, Route};
use crate::fingerprinting::names;
use crate::proxy::forwarding::forward;
use crate::proxy::handler::header_manipulation::{
    apply_request_header_manipulation, apply_response_header_manipulation,
};
use crate::proxy::handler::headers::{add_forwarded_headers, akamai_header_value};
use crate::proxy::handler::rate_limit_validation::check_rate_limit;
use crate::proxy::http_result::{HttpError, HttpResult};
use crate::proxy::ClientPool;
use crate::telemetry::metrics::values;
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
            m.record_ip_filter_denied();
            m.record_error(values::ERROR_IP_BLOCKED);
        }
        return Err(HttpError::Forbidden);
    }

    if let Some(m) = metrics {
        m.record_ip_filter_allowed();
    }

    Ok(())
}

/// Handle request routing and forwarding
#[allow(clippy::too_many_arguments)]
pub async fn handle_proxy_request(
    mut req: Request<Incoming>,
    routes: Vec<Route>,
    backends: Arc<Vec<Backend>>,
    ja4_fingerprints: Option<crate::fingerprinting::Ja4Fingerprints>,
    fingerprint_rx: Option<watch::Receiver<Option<huginn_net_http::AkamaiFingerprint>>>,
    syn_fingerprint: Option<crate::fingerprinting::TcpObservation>,
    keep_alive: &KeepAliveConfig,
    security: &crate::proxy::SecurityContext,
    metrics: Option<Arc<Metrics>>,
    peer: std::net::SocketAddr,
    is_https: bool,
    preserve_host: bool,
    client_pool: &Arc<ClientPool>,
) -> HttpResult<hyper::Response<RespBody>> {
    let start = Instant::now();
    let method = req.method().to_string();
    let protocol = format!("{:?}", req.version());

    if let Some(ref m) = metrics {
        if let Some(content_length) = req.headers().get(hyper::header::CONTENT_LENGTH) {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<u64>() {
                    m.record_bytes_received(length, &protocol);
                }
            }
        }
    }

    check_ip_access(peer, &security.ip_filter, metrics.as_ref())?;

    let path = req.uri().path();
    let route_match = if let Some(route) =
        crate::proxy::forwarding::pick_route_with_fingerprinting(path, &routes)
    {
        // Route matched: use route's fingerprinting configuration
        if let Some(ref m) = metrics {
            m.record_backend_selection(route.backend);
        }
        route
    } else {
        // No route matched: return 404
        let error = HttpError::NoMatchingRoute;
        if let Some(ref m) = metrics {
            m.record_error(error.error_type());
        }
        return Err(error);
    };

    if let Some(rate_limited_response) = check_rate_limit(
        security.rate_limit_manager.as_ref(),
        &security.rate_limit_config,
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
        if let Some(ref fingerprints) = ja4_fingerprints {
            if let Ok(hv) = hyper::header::HeaderValue::from_str(&fingerprints.ja4.full.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4), hv);
            }
            if let Ok(hv) =
                hyper::header::HeaderValue::from_str(&fingerprints.ja4_raw.full.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4_RAW), hv);
            }
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
        match syn_fingerprint {
            Some(ref syn_fp) => {
                debug!("Handler: injecting {} header: {}", names::TCP_SYN, syn_fp);
                if let Ok(hv) = hyper::header::HeaderValue::from_str(&syn_fp.to_string()) {
                    req.headers_mut()
                        .insert(HeaderName::from_static(names::TCP_SYN), hv);
                }
            }
            None => {
                debug!(
                    "Handler: no TCP SYN fingerprint available — keep-alive request or SYN not captured"
                );
            }
        }
    }

    // Add X-Forwarded-* headers after fingerprinting
    // Note: Fingerprints are extracted from TLS handshake/HTTP2 frames (before HTTP request parsing),
    // so adding these headers doesn't affect fingerprint generation
    add_forwarded_headers(&mut req, peer, is_https);

    // Apply request header manipulation (global + per-route)
    apply_request_header_manipulation(
        req.headers_mut(),
        security.global_header_manipulation.as_ref(),
        route_match.headers,
        metrics.as_ref(),
    );

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
            security_headers: Some(&security.headers),
            is_https,
            preserve_host,
            route: route_match.matched_prefix,
            client_pool,
            force_new_connection: route_match.force_new_connection,
        },
    )
    .await;

    let mut result = result;
    if let Ok(ref mut response) = result {
        if let Some(ref m) = metrics {
            if let Some(content_length) = response.headers().get(hyper::header::CONTENT_LENGTH) {
                if let Ok(length_str) = content_length.to_str() {
                    if let Ok(length) = length_str.parse::<u64>() {
                        m.record_bytes_sent(length, &protocol);
                    }
                }
            }
        }

        apply_response_header_manipulation(
            response.headers_mut(),
            security.global_header_manipulation.as_ref(),
            route_match.headers,
            metrics.as_ref(),
        );
    }

    let duration = start.elapsed().as_secs_f64();
    let status_code = match &result {
        Ok(resp) => resp.status().as_u16(),
        Err(e) => {
            let code: StatusCode = (*e).clone().into();
            code.as_u16()
        }
    };

    if let Some(ref m) = metrics {
        m.record_request(&method, status_code, &protocol, route_match.matched_prefix);
        m.record_request_duration(
            duration,
            &method,
            status_code,
            &protocol,
            route_match.matched_prefix,
        );
    }

    result
}
