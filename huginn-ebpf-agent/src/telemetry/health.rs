use crate::config::HealthFormat;
use crate::healthchecks;
use crate::telemetry::http::RespBody;
use crate::telemetry::status::{NotReadyReason, Status, StatusBody};
use hyper::Response;
use hyper::StatusCode;
use tracing::warn;

/// Health check, 200 if process is running.
pub fn health_check_response(format: HealthFormat) -> Response<RespBody> {
    StatusBody::new(Status::Healthy).render(StatusCode::OK, format)
}

/// Liveness check, 200 if process is running
pub fn live_check_response(format: HealthFormat) -> Response<RespBody> {
    StatusBody::new(Status::Alive).render(StatusCode::OK, format)
}

/// Readiness check if BPF pins exist
pub fn ready_check_response(pin_path: &str, format: HealthFormat) -> Response<RespBody> {
    if healthchecks::pins_exist(pin_path) {
        return StatusBody::new(Status::Serving).render(StatusCode::OK, format);
    }

    let reason = NotReadyReason::PinsNotReady;
    warn!(
        pin_path,
        reason = reason.as_str(),
        "Readiness check failed: BPF map pins are not present yet"
    );
    StatusBody::with_reason(Status::NotReady, reason)
        .render(StatusCode::SERVICE_UNAVAILABLE, format)
}
