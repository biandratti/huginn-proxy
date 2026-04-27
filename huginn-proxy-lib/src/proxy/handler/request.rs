use crate::backend::health_check::HealthRegistry;
use crate::backend::BackendSelector;
use crate::config::{Backend, KeepAliveConfig, Route};
use crate::fingerprinting::names;
use crate::fingerprinting::TcpObservation;
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
use http::Version;
use hyper::body::Incoming;
use hyper::header::HeaderName;
use hyper::Request;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::debug;

type RespBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

fn check_ip_access(
    peer: std::net::SocketAddr,
    ip_filter: &crate::config::IpFilterConfig,
    metrics: &Arc<Metrics>,
) -> HttpResult<()> {
    let client_ip = peer.ip();

    if !crate::security::is_ip_allowed(client_ip, ip_filter) {
        debug!(?peer, "IP blocked by filter");
        metrics.record_ip_filter_denied();
        metrics.record_error(values::ERROR_IP_BLOCKED);
        return Err(HttpError::Forbidden);
    }

    metrics.record_ip_filter_allowed();
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
    syn_fingerprint: Option<TcpObservation>,
    keep_alive: &KeepAliveConfig,
    security: &crate::proxy::SecurityContext,
    metrics: Arc<Metrics>,
    peer: std::net::SocketAddr,
    is_https: bool,
    preserve_host: bool,
    client_pool: &Arc<ClientPool>,
    health_registry: &HealthRegistry,
    backend_selector: &BackendSelector,
) -> HttpResult<hyper::Response<RespBody>> {
    let start = Instant::now();
    let method = req.method().to_string();
    let protocol = format!("{:?}", req.version());

    if let Some(content_length) = req.headers().get(hyper::header::CONTENT_LENGTH) {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<u64>() {
                metrics.record_bytes_received(length, &protocol);
            }
        }
    }

    check_ip_access(peer, &security.ip_filter, &metrics)?;

    let path = req.uri().path();
    let route_match = if let Some(route) =
        crate::proxy::forwarding::pick_route_with_fingerprinting(path, &routes)
    {
        route
    } else {
        let error = HttpError::NoMatchingRoute;
        metrics.record_error(error.error_type());
        return Err(error);
    };

    let selected_backend = match backend_selector.select(
        route_match.matched_prefix,
        &route_match.backend_candidates,
        health_registry,
    ) {
        Some(addr) => addr,
        None => {
            // Keep one stable backend label for metrics when all candidates are unhealthy.
            let label = route_match
                .backend_candidates
                .first()
                .copied()
                .unwrap_or(route_match.backend);
            metrics.record_health_check_gate_reject(label);
            return Err(HttpError::UpstreamUnhealthy);
        }
    };
    metrics.record_backend_selection(&selected_backend);

    if let Some(rate_limited_response) = check_rate_limit(
        security.rate_limit_manager.as_ref(),
        &security.rate_limit_config,
        &route_match,
        peer,
        req.headers(),
        &metrics,
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
            if let Ok(hv) = hyper::header::HeaderValue::from_str(&fingerprints.ja4.raw.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4_R), hv);
            }
            if let Ok(hv) =
                hyper::header::HeaderValue::from_str(&fingerprints.ja4_raw.full.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4_O), hv);
            }
            if let Ok(hv) =
                hyper::header::HeaderValue::from_str(&fingerprints.ja4_raw.raw.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4_OR), hv);
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
                    metrics.record_http2_fingerprint_failure();
                }
            } else {
                debug!("Handler: HTTP/1.1 connection, Akamai fingerprint not applicable");
                metrics.record_http2_fingerprint_not_applicable();
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
                    "Handler: no TCP SYN fingerprint available - keep-alive request or SYN not captured"
                );
            }
        }
    }

    // Add X-Forwarded-* headers after fingerprinting
    let sni = ja4_fingerprints.as_ref().and_then(|fp| fp.sni.as_deref());
    add_forwarded_headers(&mut req, peer, is_https, sni);

    apply_request_header_manipulation(
        req.headers_mut(),
        security.global_header_manipulation.as_ref(),
        route_match.headers,
        &metrics,
    );

    let result = forward(
        req,
        selected_backend,
        crate::proxy::forwarding::ForwardConfig {
            backends: &backends,
            keep_alive,
            metrics: Arc::clone(&metrics),
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
        if let Some(content_length) = response.headers().get(hyper::header::CONTENT_LENGTH) {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<u64>() {
                    metrics.record_bytes_sent(length, &protocol);
                }
            }
        }

        apply_response_header_manipulation(
            response.headers_mut(),
            security.global_header_manipulation.as_ref(),
            route_match.headers,
            &metrics,
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

    metrics.record_request(&method, status_code, &protocol, route_match.matched_prefix);
    metrics.record_request_duration(
        duration,
        &method,
        status_code,
        &protocol,
        route_match.matched_prefix,
    );

    result
}
