use crate::healthchecks;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::Response;
use hyper::StatusCode;
use serde_json::json;

type RespBody = BoxBody<Bytes, hyper::Error>;

/// Health check, 200 if process is running.
pub fn health_check_response(
) -> Result<Response<RespBody>, Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({"status": "healthy"});
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("Failed to serialize health response: {e}"))?;
    let body = Full::new(Bytes::from(body_bytes))
        .map_err(|never| match never {})
        .boxed();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("Failed to build response: {e}"))?;
    Ok(response)
}

/// Liveness check, 200 if process is running
pub fn live_check_response() -> Result<Response<RespBody>, Box<dyn std::error::Error + Send + Sync>>
{
    let body = json!({"status": "alive"});
    let body_bytes =
        serde_json::to_vec(&body).map_err(|e| format!("Failed to serialize live response: {e}"))?;
    let body = Full::new(Bytes::from(body_bytes))
        .map_err(|never| match never {})
        .boxed();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("Failed to build response: {e}"))?;
    Ok(response)
}

/// Readiness check if BPF pins exist
pub fn ready_check_response(
    pin_path: &str,
) -> Result<Response<RespBody>, Box<dyn std::error::Error + Send + Sync>> {
    let (status, body) = if healthchecks::pins_exist(pin_path) {
        (StatusCode::OK, json!({"status": "ready"}))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "not_ready", "reason": "pins_not_ready"}),
        )
    };
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| format!("Failed to serialize ready response: {e}"))?;
    let body = Full::new(Bytes::from(body_bytes))
        .map_err(|never| match never {})
        .boxed();
    let response = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("Failed to build response: {e}"))?;
    Ok(response)
}
