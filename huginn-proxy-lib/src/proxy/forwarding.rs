use crate::config::BackendHttpVersion;
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
use tokio::time::Instant;

type HttpClient = Client<HttpConnector, Incoming>;
type RespBody = BoxBody<bytes::Bytes, hyper::Error>;

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

fn create_client(http_version: Version) -> HttpClient {
    let connector = HttpConnector::new();
    let mut builder = Client::builder(TokioExecutor::new());

    match http_version {
        Version::HTTP_2 => {
            builder.http2_only(true);
        }
        Version::HTTP_11 => {
            // HTTP/1.1 is the default, no special configuration needed
        }
        _ => {
            // For other versions, default to HTTP/1.1
        }
    }

    builder.build(connector)
}

pub async fn forward(
    mut req: Request<Incoming>,
    backend: String,
    backends: &[crate::config::Backend],
    metrics: Option<Arc<Metrics>>,
) -> HttpResult<Response<RespBody>> {
    let start = Instant::now();
    let protocol = format!("{:?}", req.version());
    let uri = format!(
        "http://{}{}",
        backend,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("")
    )
    .parse::<http::Uri>()
    .map_err(|e| HttpError::InvalidUri(e.to_string()))?;

    let client_version = req.version();
    let backend_config = find_backend_config(&backend, backends);
    let target_version = determine_http_version(backend_config, client_version, false);

    if req.version() != target_version {
        *req.version_mut() = target_version;
    }

    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    let out_req = Request::from_parts(parts, body);

    let client = create_client(target_version);
    let result = client.request(out_req).await;

    let duration = start.elapsed().as_secs_f64();

    match result {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            if let Some(ref m) = metrics {
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
            if let Some(ref m) = metrics {
                m.backend_errors_total.add(
                    1,
                    &[
                        KeyValue::new("backend_address", backend.clone()),
                        KeyValue::new("error_type", "request_failed"),
                    ],
                );
            }
            Err(HttpError::FailedToGetResponseFromBackend(e.to_string()))
        }
    }
}

pub fn pick_route<'a>(path: &str, routes: &'a [crate::config::Route]) -> Option<&'a str> {
    routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
        .map(|r| r.backend.as_str())
}
