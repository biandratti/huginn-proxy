use crate::telemetry::http::{json_response, RespBody};
use crate::telemetry::status::{Status, StatusBody};
use crate::telemetry::{health, metrics_handler};
use hyper::{Response, StatusCode};
use prometheus::Registry;
use tracing::warn;

pub fn dispatch(path: &str, registry: &Registry, pin_path: &str) -> Response<RespBody> {
    match path {
        "/metrics" => metrics_handler::handle_metrics(registry).unwrap_or_else(|e| {
            warn!(error = %e, "Failed to encode metrics");
            json_response(StatusCode::INTERNAL_SERVER_ERROR, StatusBody::new(Status::Error))
        }),
        "/health" => health::health_check_response(),
        "/ready" => health::ready_check_response(pin_path),
        "/live" => health::live_check_response(),
        _ => json_response(StatusCode::NOT_FOUND, StatusBody::new(Status::NotFound)),
    }
}
