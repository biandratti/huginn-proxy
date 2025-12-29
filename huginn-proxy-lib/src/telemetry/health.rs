use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::Response;
use hyper::StatusCode;
use serde_json::json;

use crate::config::Backend;
use crate::error::Result;

type RespBody = BoxBody<Bytes, hyper::Error>;

/// Health check response - always returns 200 if process is running
pub fn health_check_response() -> Result<Response<RespBody>> {
    let body = json!({"status": "healthy"});
    let body_bytes = serde_json::to_vec(&body).map_err(|e| {
        crate::error::ProxyError::Http(format!("Failed to serialize health response: {e}"))
    })?;

    let body = Full::new(Bytes::from(body_bytes))
        .map_err(|never| match never {})
        .boxed();

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| {
            crate::error::ProxyError::Http(format!("Failed to build health response: {e}"))
        })?;

    Ok(response)
}

/// Readiness check - verifies that backends are available
/// Returns 200 if at least one backend is configured, 503 otherwise
pub fn ready_check_response(backends: &[Backend]) -> Result<Response<RespBody>> {
    if backends.is_empty() {
        let body = json!({
            "status": "not_ready",
            "reason": "no_backends_configured"
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            crate::error::ProxyError::Http(format!("Failed to serialize ready response: {e}"))
        })?;

        let body = Full::new(Bytes::from(body_bytes))
            .map_err(|never| match never {})
            .boxed();

        let response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| {
                crate::error::ProxyError::Http(format!("Failed to build ready response: {e}"))
            })?;

        Ok(response)
    } else {
        let body = json!({"status": "ready"});
        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            crate::error::ProxyError::Http(format!("Failed to serialize ready response: {e}"))
        })?;

        let body = Full::new(Bytes::from(body_bytes))
            .map_err(|never| match never {})
            .boxed();

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| {
                crate::error::ProxyError::Http(format!("Failed to build ready response: {e}"))
            })?;

        Ok(response)
    }
}

/// Liveness check - always returns 200 if process is running
pub fn live_check_response() -> Result<Response<RespBody>> {
    let body = json!({"status": "alive"});
    let body_bytes = serde_json::to_vec(&body).map_err(|e| {
        crate::error::ProxyError::Http(format!("Failed to serialize live response: {e}"))
    })?;

    let body = Full::new(Bytes::from(body_bytes))
        .map_err(|never| match never {})
        .boxed();

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| {
            crate::error::ProxyError::Http(format!("Failed to build live response: {e}"))
        })?;

    Ok(response)
}
