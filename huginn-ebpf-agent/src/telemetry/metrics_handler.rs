use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::Response;
use hyper::StatusCode;
use prometheus::{Encoder, Registry, TextEncoder};

type RespBody = BoxBody<Bytes, hyper::Error>;

pub fn handle_metrics(
    registry: &Registry,
) -> Result<Response<RespBody>, Box<dyn std::error::Error + Send + Sync>> {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| format!("Failed to encode metrics: {e}"))?;

    let body = Full::new(Bytes::from(buffer))
        .map_err(|never| match never {})
        .boxed();

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", encoder.format_type())
        .body(body)
        .map_err(|e| format!("Failed to build response: {e}"))?;

    Ok(response)
}
