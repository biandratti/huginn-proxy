use crate::backend::UpstreamGateway;
use crate::config::{Backend, Domain, KeepAliveConfig};
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
use http::HeaderMap;
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

/// Strip all proxy-authoritative fingerprint headers from an incoming request.
///
/// Returns the names of the fingerprint headers the client actually supplied.
/// A non-empty return value means the client attempted to spoof those signatures.
///
/// The detection header ([`names::SPOOFING_DETECTED`]) is also stripped here,
/// so the client cannot forge or suppress the detection signal.
pub fn strip_client_fingerprints(headers: &mut HeaderMap) -> Vec<&'static str> {
    let mut spoofed = Vec::new();
    for &name in names::FINGERPRINTS {
        if headers.remove(name).is_some() {
            spoofed.push(name);
        }
    }
    headers.remove(names::SPOOFING_DETECTED);
    spoofed
}

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
    domains: Arc<Vec<Domain>>,
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
    upstream: &UpstreamGateway,
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

    if let Err(e) = check_ip_access(peer, &security.ip_filter, &metrics) {
        let status_code = StatusCode::from(e.clone()).as_u16();
        metrics.record_entrypoint_request(&method, status_code, &protocol);
        return Err(e);
    }

    let path = req.uri().path();
    let host = extract_request_host(&req, ja4_fingerprints.as_ref(), is_https);

    let domain = crate::proxy::router::pick_domain(&domains, &host);

    let route_match = match domain {
        None => {
            let error = HttpError::MisdirectedRequest;
            metrics.record_error(error.error_type());
            let status_code = StatusCode::from(error.clone()).as_u16();
            metrics.record_entrypoint_request(&method, status_code, &protocol);
            return Err(error);
        }
        Some(d) => match crate::proxy::router::pick_route_with_fingerprinting(path, &d.routes) {
            Some(r) => r,
            None => {
                let error = HttpError::NoMatchingRoute;
                metrics.record_error(error.error_type());
                let status_code = StatusCode::from(error.clone()).as_u16();
                metrics.record_entrypoint_request(&method, status_code, &protocol);
                return Err(error);
            }
        },
    };

    let selected_upstream = match upstream.selector.select(
        route_match.matched_prefix,
        &route_match.backend_candidates,
        &upstream.health,
    ) {
        Some(addr) => addr,
        None => {
            metrics.record_health_check_gate_reject(route_match.backend);
            let error = HttpError::UpstreamUnhealthy;
            let status_code = StatusCode::from(error.clone()).as_u16();
            metrics.record_entrypoint_request(&method, status_code, &protocol);
            metrics.record_request(&method, status_code, &protocol, route_match.matched_prefix);
            metrics.record_request_duration(
                start.elapsed().as_secs_f64(),
                &method,
                status_code,
                &protocol,
                route_match.matched_prefix,
            );
            return Err(error);
        }
    };
    metrics.record_backend_selection(&selected_upstream);

    if let Some(rate_limited_response) = check_rate_limit(
        security.rate_limit_manager.as_ref(),
        &security.rate_limit_config,
        &route_match,
        peer,
        req.headers(),
        &metrics,
    ) {
        let status_code = rate_limited_response.status().as_u16();
        metrics.record_entrypoint_request(&method, status_code, &protocol);
        metrics.record_request(&method, status_code, &protocol, route_match.matched_prefix);
        metrics.record_request_duration(
            start.elapsed().as_secs_f64(),
            &method,
            status_code,
            &protocol,
            route_match.matched_prefix,
        );
        return Ok(rate_limited_response);
    }

    // Strip proxy-authoritative fingerprint headers unconditionally, must run outside the
    // fingerprinting gate, so routes with fingerprinting=false also strip spoofed values.
    let spoofed = strip_client_fingerprints(req.headers_mut());
    for &name in &spoofed {
        metrics.record_fingerprint_spoofing_attempt(name);
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
                hyper::header::HeaderValue::from_str(&fingerprints.ja4_original.full.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4_O), hv);
            }
            if let Ok(hv) =
                hyper::header::HeaderValue::from_str(&fingerprints.ja4_original.raw.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4_OR), hv);
            }
            if let Ok(hv) =
                hyper::header::HeaderValue::from_str(&fingerprints.ja4_stable_v1.full.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4_S1), hv);
            }
            if let Ok(hv) =
                hyper::header::HeaderValue::from_str(&fingerprints.ja4_stable_v1.raw.to_string())
            {
                req.headers_mut()
                    .insert(HeaderName::from_static(names::TLS_JA4_S1R), hv);
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

    // Signal which fingerprint signatures the client attempted to spoof.
    // Runs outside the fingerprinting gate so backends on fingerprinting=false routes
    // also receive the detection signal.
    if !spoofed.is_empty() {
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&spoofed.join(",")) {
            req.headers_mut()
                .insert(HeaderName::from_static(names::SPOOFING_DETECTED), hv);
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
        selected_upstream,
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

    metrics.record_entrypoint_request(&method, status_code, &protocol);
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

// TODO: WIP
/// Extract the effective hostname for domain matching.
///
/// Priority:
/// 1. TLS SNI — authoritative; set by the TLS layer before any HTTP is read.
/// 2. HTTP/2 URI authority — `:authority` pseudo-header is part of the HTTP/2
///    framing and reflects the real connection target. The `Host` header is a
///    regular application-level header that a client can set to anything; it is
///    deliberately NOT used for HTTP/2 to prevent spoofing.
/// 3. HTTP/1.1 `Host` header — only option available for HTTP/1.1 connections.
///
/// IPv6 addresses are returned WITHOUT brackets (`::1` not `[::1]`) matching
/// what `http::Uri::host()` and the domain config both use as canonical form.
fn extract_request_host(
    req: &Request<Incoming>,
    ja4: Option<&crate::fingerprinting::Ja4Fingerprints>,
    is_https: bool,
) -> String {
    // 1. TLS SNI
    if is_https {
        if let Some(sni) = ja4.and_then(|fp| fp.sni.as_deref()) {
            return sni.to_string();
        }
    }
    // 2. URI authority — present for HTTP/2 and absolute-form HTTP/1.1.
    //    strip_host_port normalises IPv6: http::Uri::host() returns "[::1]" (with
    //    brackets); strip_host_port strips them to "::1" to match the domain config.
    if let Some(raw) = req.uri().host() {
        let host = strip_host_port(raw);
        if !host.is_empty() {
            return host.to_string();
        }
    }
    // 3. Host header fallback (HTTP/1.1 origin-form, or HTTP/2 without :authority)
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_host_port)
        .map(str::to_string)
        .unwrap_or_default()
}

/// Strip port from a `Host` header value and normalise IPv6 addresses.
///
/// Returns the bare hostname without port and without IPv6 brackets:
/// - `"[::1]:8080"` → `"::1"`
/// - `"[::1]"` → `"::1"`
/// - `"example.com:8080"` → `"example.com"`
/// - `"127.0.0.1:7000"` → `"127.0.0.1"`
fn strip_host_port(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6: strip leading '[' and everything from ']' onward.
        host.find(']').map_or(host, |end| &host[1..end])
    } else {
        host.split_once(':').map_or(host, |(h, _)| h)
    }
}
