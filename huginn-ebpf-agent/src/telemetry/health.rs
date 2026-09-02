use crate::config::HealthFormat;
use crate::healthchecks::AgentHealth;
use crate::telemetry::http::RespBody;
use crate::telemetry::status::{Status, StatusBody};
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

/// Readiness check: attached in-process, required pins present, not draining.
pub fn ready_check_response(health: &AgentHealth, format: HealthFormat) -> Response<RespBody> {
    if let Some(reason) = health.not_ready_reason() {
        warn!(pin_path = health.pin_path(), reason = reason.as_str(), "Readiness check failed");
        return StatusBody::with_reason(Status::NotReady, reason)
            .render(StatusCode::SERVICE_UNAVAILABLE, format);
    }
    StatusBody::new(Status::Serving).render(StatusCode::OK, format)
}
