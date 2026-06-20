//! HTTP routing for the observability server: maps a request path to the matching
//! health/metrics handler and centralises the JSON 404 / 500 fallbacks.

use hyper::{Response, StatusCode};
use prometheus::Registry;
use tracing::warn;

use crate::telemetry::status::{Status, StatusBody};
use crate::telemetry::{
    handle_metrics, health_check_response, live_check_response, ready_check_response, Readiness,
};
use crate::utils::http::{json_response, RespBody};

/// Route an observability request. Health endpoints are infallible; metrics may fail to
/// encode and falls back to a JSON 500. Unknown paths return a JSON 404.
pub fn dispatch(path: &str, registry: &Registry, readiness: &Readiness) -> Response<RespBody> {
    match path {
        "/health" => health_check_response(),
        "/ready" => ready_check_response(readiness.is_ready()),
        "/live" => live_check_response(),
        "/metrics" => handle_metrics(registry).unwrap_or_else(|e| {
            warn!(error = %e, "Failed to encode metrics");
            json_response(StatusCode::INTERNAL_SERVER_ERROR, StatusBody::new(Status::Error))
        }),
        _ => json_response(StatusCode::NOT_FOUND, StatusBody::new(Status::NotFound)),
    }
}
