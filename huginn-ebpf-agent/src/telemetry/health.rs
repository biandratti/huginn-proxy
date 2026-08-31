use crate::config::HealthFormat;
use crate::healthchecks::AgentHealth;
use crate::telemetry::http::{json_response, text_response, RespBody};
use crate::telemetry::status::{Status, StatusBody};
use hyper::Response;
use hyper::StatusCode;
use tracing::warn;

pub(crate) fn render(
    http_status: StatusCode,
    body: StatusBody,
    format: HealthFormat,
) -> Response<RespBody> {
    match format {
        HealthFormat::Json => json_response(http_status, body),
        HealthFormat::Text => text_response(http_status, body.agent_text_token()),
    }
}

/// Health check, 200 if process is running.
pub fn health_check_response(format: HealthFormat) -> Response<RespBody> {
    render(StatusCode::OK, StatusBody::new(Status::Healthy), format)
}

/// Liveness check, 200 if process is running
pub fn live_check_response(format: HealthFormat) -> Response<RespBody> {
    render(StatusCode::OK, StatusBody::new(Status::Alive), format)
}

/// Readiness check: attached in-process, required pins present, not draining.
pub fn ready_check_response(health: &AgentHealth, format: HealthFormat) -> Response<RespBody> {
    if let Some(reason) = health.not_ready_reason() {
        warn!(pin_path = health.pin_path(), reason = reason.as_str(), "Readiness check failed");
        return render(
            StatusCode::SERVICE_UNAVAILABLE,
            StatusBody::with_reason(Status::NotReady, reason),
            format,
        );
    }
    render(StatusCode::OK, StatusBody::new(Status::Serving), format)
}
