use crate::healthchecks;
use crate::telemetry::http::{json_response, RespBody};
use crate::telemetry::status::{Status, StatusBody};
use hyper::Response;
use hyper::StatusCode;
use tracing::warn;

/// Health check, 200 if process is running.
pub fn health_check_response() -> Response<RespBody> {
    json_response(StatusCode::OK, StatusBody::new(Status::Healthy))
}

/// Liveness check, 200 if process is running
pub fn live_check_response() -> Response<RespBody> {
    json_response(StatusCode::OK, StatusBody::new(Status::Alive))
}

/// Readiness check if BPF pins exist
pub fn ready_check_response(pin_path: &str) -> Response<RespBody> {
    if healthchecks::pins_exist(pin_path) {
        return json_response(StatusCode::OK, StatusBody::new(Status::Ready));
    }

    let reason = "pins_not_ready";
    warn!(pin_path, reason, "Readiness check failed: BPF map pins are not present yet");
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        StatusBody::with_reason(Status::NotReady, reason),
    )
}
