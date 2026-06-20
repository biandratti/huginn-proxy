use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::Response;
use hyper::StatusCode;
use serde_json::json;
use tracing::warn;

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

/// Readiness check - reports whether the proxy has finished starting up and is
/// accepting connections.
///
/// Decoupled from backend availability on purpose: a proxy can serve traffic even when
/// every backend is down (that surfaces as 502s on real requests plus backend-health
/// metrics, not as readiness). Tying readiness to backends would keep the pod out of
/// rotation forever when backends are registered dynamically. This mirrors Traefik/Envoy.
///
/// `ready` is `false` while the listeners are still binding/initialising and during
/// graceful shutdown; `true` once the proxy is accepting connections.
pub fn ready_check_response(ready: bool) -> Result<Response<RespBody>> {
    if !ready {
        let reason = "proxy_starting";
        warn!(reason, "Readiness check failed: proxy is not accepting connections yet");

        let body = json!({
            "status": "not_ready",
            "reason": reason
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
