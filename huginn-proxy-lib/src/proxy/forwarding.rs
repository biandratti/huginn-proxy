use crate::config::{BackendHttpVersion, KeepAliveConfig};
use crate::proxy::http_result::{HttpError, HttpResult};
use crate::telemetry::Metrics;
use http::{Request, Response, Version};
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use opentelemetry::KeyValue;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

type HttpClient = Client<HttpConnector, Incoming>;
type RespBody = BoxBody<bytes::Bytes, hyper::Error>;

#[derive(Debug, Clone)]
pub struct RouteMatch<'a> {
    pub backend: &'a str,
    pub fingerprinting: bool,
    pub matched_prefix: &'a str,
    pub replace_path: Option<&'a str>,
    pub rate_limit: Option<&'a crate::config::RouteRateLimitConfig>,
    pub headers: Option<&'a crate::config::HeaderManipulation>,
}

pub struct ForwardConfig<'a> {
    pub backends: &'a [crate::config::Backend],
    pub keep_alive: &'a KeepAliveConfig,
    pub metrics: Option<Arc<Metrics>>,
    pub matched_prefix: &'a str,
    pub replace_path: Option<&'a str>,
    pub security_headers: Option<&'a crate::config::SecurityHeaders>,
    pub is_https: bool,
    pub preserve_host: bool,
}

pub fn find_backend_config<'a>(
    address: &str,
    backends: &'a [crate::config::Backend],
) -> Option<&'a crate::config::Backend> {
    backends.iter().find(|b| b.address == address)
}

pub fn determine_http_version(
    backend_config: Option<&crate::config::Backend>,
    client_version: Version,
    is_https: bool,
) -> Version {
    let http_version = backend_config
        .and_then(|b| b.http_version)
        .unwrap_or(if is_https {
            BackendHttpVersion::Preserve
        } else {
            BackendHttpVersion::Http11
        });

    match http_version {
        BackendHttpVersion::Http11 => Version::HTTP_11,
        BackendHttpVersion::Http2 => Version::HTTP_2,
        BackendHttpVersion::Preserve => {
            // Preserve client version, but HTTP/3 is not supported, convert to HTTP/2
            if client_version == Version::HTTP_3 {
                Version::HTTP_2
            } else {
                client_version
            }
        }
    }
}

pub fn create_client(http_version: Version, keep_alive: &KeepAliveConfig) -> HttpClient {
    let mut connector = HttpConnector::new();
    // This sets the TCP keep-alive timeout for idle connections
    if keep_alive.enabled {
        connector.set_keepalive(Some(Duration::from_secs(keep_alive.timeout_secs)));
    } else {
        connector.set_keepalive(None);
    }

    let mut builder = Client::builder(TokioExecutor::new());

    match http_version {
        Version::HTTP_2 => {
            // HTTP/2 uses persistent connections by default with native multiplexing
            builder.http2_only(true);
        }
        Version::HTTP_11 => {
            // HTTP/1.1 keep-alive is configured via connector.set_keepalive() above
        }
        _ => {
            // For other versions, default to HTTP/1.1 (keep-alive configured above)
        }
    }

    builder.build(connector)
}

pub async fn forward(
    mut req: Request<Incoming>,
    backend: String,
    config: ForwardConfig<'_>,
) -> HttpResult<Response<RespBody>> {
    let start = Instant::now();
    let protocol = format!("{:?}", req.version());

    let org_pq = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .as_bytes();

    // Replace some parts of path if replace_path is enabled for chosen upstream
    let new_pq = match config.replace_path {
        Some(new_path) => {
            let matched_path: &[u8] = config.matched_prefix.as_bytes();
            if matched_path.is_empty() || org_pq.len() < matched_path.len() {
                return Err(HttpError::InvalidUri("Path and query is broken".to_string()));
            }
            let remaining_len = org_pq.len().saturating_sub(matched_path.len());
            let capacity = remaining_len.saturating_add(new_path.len());
            let mut new_pq = Vec::<u8>::with_capacity(capacity);
            new_pq.extend_from_slice(new_path.as_bytes());
            new_pq.extend_from_slice(&org_pq[matched_path.len()..]);
            new_pq
        }
        None => org_pq.to_vec(),
    };

    let new_path_str = String::from_utf8(new_pq)
        .map_err(|e| HttpError::InvalidUri(format!("Invalid UTF-8 in path: {}", e)))?;

    let uri = format!("http://{}{}", backend, new_path_str)
        .parse::<http::Uri>()
        .map_err(|e| HttpError::InvalidUri(e.to_string()))?;

    let client_version = req.version();
    let backend_config = find_backend_config(&backend, config.backends);
    let target_version = determine_http_version(backend_config, client_version, false);

    if req.version() != target_version {
        *req.version_mut() = target_version;
    }

    let (mut parts, body) = req.into_parts();

    if let Some(ref m) = config.metrics {
        if let Some(content_length) = parts.headers.get(hyper::header::CONTENT_LENGTH) {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<u64>() {
                    m.backend_bytes_sent_total
                        .add(length, &[KeyValue::new("backend_address", backend.clone())]);
                }
            }
        }
    }

    let original_host = config
        .preserve_host
        .then(|| parts.headers.get("host").cloned())
        .flatten();
    parts.uri = uri;
    if let Some(host) = original_host {
        parts.headers.insert("host", host);
    }

    let out_req = Request::from_parts(parts, body);

    let client = create_client(target_version, config.keep_alive);
    let result = client.request(out_req).await;

    let duration = start.elapsed().as_secs_f64();

    match result {
        Ok(mut resp) => {
            let status_code = resp.status().as_u16();

            if let Some(ref m) = config.metrics {
                if let Some(content_length) = resp.headers().get(hyper::header::CONTENT_LENGTH) {
                    if let Ok(length_str) = content_length.to_str() {
                        if let Ok(length) = length_str.parse::<u64>() {
                            m.backend_bytes_received_total
                                .add(length, &[KeyValue::new("backend_address", backend.clone())]);
                        }
                    }
                }
            }

            crate::security::apply_security_headers(
                &mut resp,
                config.security_headers,
                config.is_https,
            );

            if let Some(ref m) = config.metrics {
                m.backend_requests_total.add(
                    1,
                    &[
                        KeyValue::new("backend_address", backend.clone()),
                        KeyValue::new("status_code", status_code.to_string()),
                        KeyValue::new("protocol", protocol.clone()),
                    ],
                );
                m.backend_duration_seconds.record(
                    duration,
                    &[
                        KeyValue::new("backend_address", backend.clone()),
                        KeyValue::new("status_code", status_code.to_string()),
                        KeyValue::new("protocol", protocol),
                    ],
                );
            }
            Ok(resp.map(|b| b.boxed()))
        }
        Err(e) => {
            let error = HttpError::FailedToGetResponseFromBackend(e.to_string());
            if let Some(ref m) = config.metrics {
                m.backend_errors_total.add(
                    1,
                    &[
                        KeyValue::new("backend_address", backend.clone()),
                        KeyValue::new("error_type", error.error_type()),
                    ],
                );
            }
            Err(error)
        }
    }
}

pub fn pick_route<'a>(path: &str, routes: &'a [crate::config::Route]) -> Option<&'a str> {
    routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
        .map(|r| r.backend.as_str())
}

pub fn pick_route_with_fingerprinting<'a>(
    path: &str,
    routes: &'a [crate::config::Route],
) -> Option<RouteMatch<'a>> {
    routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
        .map(|r| RouteMatch {
            backend: r.backend.as_str(),
            fingerprinting: r.fingerprinting,
            matched_prefix: r.prefix.as_str(),
            replace_path: r.replace_path.as_deref(),
            rate_limit: r.rate_limit.as_ref(),
            headers: r.headers.as_ref(),
        })
}
