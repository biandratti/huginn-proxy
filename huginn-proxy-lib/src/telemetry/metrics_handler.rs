use hyper::Response;
use hyper::StatusCode;
use prometheus::{Encoder, TextEncoder};

use crate::error::Result;
use crate::utils::http::{full_body, RespBody};

pub fn handle_metrics(registry: &prometheus::Registry) -> Result<Response<RespBody>> {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();

    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| crate::error::ProxyError::Http(format!("Failed to encode metrics: {e}")))?;

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", encoder.format_type())
        .body(full_body(buffer))
        .map_err(|e| crate::error::ProxyError::Http(format!("Failed to build response: {e}")))
}
