use super::host::extract_request_host;
use crate::backend::UpstreamGateway;
use crate::config::{Backend, Domain, KeepAliveConfig, DEFAULT_DOMAIN_LABEL};
use crate::fingerprinting::names;
use crate::fingerprinting::TcpObservation;
use crate::proxy::forwarding::forward;
use crate::proxy::handler::header_manipulation::{
    apply_request_header_manipulation, apply_response_header_manipulation,
};
use crate::proxy::handler::headers::{add_forwarded_headers, akamai_header_value};
use crate::proxy::handler::rate_limit_validation::check_rate_limit;
use crate::proxy::handler::resolve::{domain_defers_ip_filter, resolve_security};
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

use crate::utils::http::RespBody;

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

/// Enforce the IP ACL, recording the entrypoint-request metric on rejection. Shared by the
/// pre-routing (domain-effective) and post-routing (route-effective) check sites.
fn enforce_ip_access(
    peer: std::net::SocketAddr,
    ip_filter: &crate::config::IpFilterConfig,
    metrics: &Arc<Metrics>,
    method: &str,
    protocol: &str,
) -> HttpResult<()> {
    if let Err(e) = check_ip_access(peer, ip_filter, metrics) {
        let status_code = StatusCode::from(e.clone()).as_u16();
        metrics.record_entrypoint_request(method, status_code, protocol);
        return Err(e);
    }
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
    connection_sni: Option<&str>,
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

    let path = req.uri().path();
    let host = extract_request_host(&req);

    let domain = crate::proxy::router::pick_domain(&domains, &host);
    let domain_headers = domain.and_then(|d| d.headers.as_ref());
    let domain_label: &str = domain.map_or(DEFAULT_DOMAIN_LABEL, Domain::label);

    // Rate-limit base is `domain.or(global)`; the route override is applied in `check_rate_limit`.
    let domain_security = domain.and_then(|d| d.security.as_ref());
    let effective_rate_limit = domain_security
        .and_then(|s| s.rate_limit.as_ref())
        .unwrap_or(&security.rate_limit_config);

    // If no route overrides the IP filter, the domain/global filter applies to every route, so
    // enforce it pre-routing (a blocked client never learns whether a host/route exists). If a
    // route does override it, defer to post-routing (route-level ACL; see `resolve_security`).
    let defer_ip_check = domain.is_some_and(domain_defers_ip_filter);
    if !defer_ip_check {
        let domain_ip_filter = domain_security
            .and_then(|s| s.ip_filter.as_ref())
            .unwrap_or(&security.ip_filter);
        enforce_ip_access(peer, domain_ip_filter, &metrics, &method, &protocol)?;
    }

    // Misdirected-request enforcement (RFC 9110 §15.5.20 / RFC 7540 §9.1.2), always on,
    // the same default protection nginx and Apache `mod_http2` apply: a reused (coalesced)
    // TLS connection may carry requests whose `:authority` / `Host` differs from the SNI
    // that selected the connection's certificate. Reject with 421 when that host is served
    // by a *different* certificate (same-cert / wildcard / SAN coalescing is allowed). Only
    // fires on TLS connections that presented an SNI; runs after the IP filter so a blocked
    // client never learns whether a host exists.
    if let Some(sni) = connection_sni {
        if !crate::proxy::router::authority_matches_sni(&domains, sni, &host) {
            debug!(
                ?peer,
                sni,
                host = %host,
                "421 Misdirected Request: host not covered by the connection's certificate (SNI)"
            );
            let error = HttpError::MisdirectedRequest;
            metrics.record_error(error.error_type());
            let status_code = StatusCode::from(error.clone()).as_u16();
            metrics.record_entrypoint_request(&method, status_code, &protocol);
            return Err(error);
        }
    }

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

    // Route is known: resolve the whole-block effective policy (route.or(domain).or(global)).
    let effective = resolve_security(security, domain, &route_match);

    // Deferred route-level IP check, before backend selection (blocked client never hits upstream).
    if defer_ip_check {
        enforce_ip_access(peer, effective.ip_filter, &metrics, &method, &protocol)?;
    }

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
            metrics.record_request(
                &method,
                status_code,
                &protocol,
                route_match.matched_prefix,
                domain_label,
            );
            metrics.record_request_duration(
                start.elapsed().as_secs_f64(),
                &method,
                status_code,
                &protocol,
                route_match.matched_prefix,
                domain_label,
            );
            return Err(error);
        }
    };
    metrics.record_backend_selection(&selected_upstream);

    if let Some(rate_limited_response) = check_rate_limit(
        security.rate_limit_manager.as_ref(),
        effective_rate_limit,
        &route_match,
        peer,
        req.headers(),
        &metrics,
        domain_label,
        &security.trusted_proxies,
    ) {
        let status_code = rate_limited_response.status().as_u16();
        metrics.record_entrypoint_request(&method, status_code, &protocol);
        metrics.record_request(
            &method,
            status_code,
            &protocol,
            route_match.matched_prefix,
            domain_label,
        );
        metrics.record_request_duration(
            start.elapsed().as_secs_f64(),
            &method,
            status_code,
            &protocol,
            route_match.matched_prefix,
            domain_label,
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
    if effective.fingerprinting {
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

    // Add X-Forwarded-* headers after fingerprinting. X-Forwarded-Host mirrors the resolved
    // routing host (`host`) so it agrees with the backend the request is sent to, even for
    // coalesced HTTP/2 connections where `:authority` differs from the connection SNI.
    add_forwarded_headers(&mut req, peer, is_https, &host);

    apply_request_header_manipulation(
        req.headers_mut(),
        security.global_header_manipulation.as_ref(),
        domain_headers,
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
            security_headers: Some(effective.security_headers),
            is_https,
            preserve_host,
            route: route_match.matched_prefix,
            domain: domain_label,
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
            domain_headers,
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
    metrics.record_request(
        &method,
        status_code,
        &protocol,
        route_match.matched_prefix,
        domain_label,
    );
    metrics.record_request_duration(
        duration,
        &method,
        status_code,
        &protocol,
        route_match.matched_prefix,
        domain_label,
    );

    result
}
