use crate::config::HealthFormat;
use crate::healthchecks;
use crate::telemetry::http::{json_response, text_response, RespBody};
use crate::telemetry::status::{NotReadyReason, Status, StatusBody};
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

/// Readiness check if BPF pins exist
pub fn ready_check_response(pin_path: &str, format: HealthFormat) -> Response<RespBody> {
    if healthchecks::pins_exist(pin_path) {
        return render(StatusCode::OK, StatusBody::new(Status::Serving), format);
    }

    let reason = NotReadyReason::PinsNotReady;
    warn!(
        pin_path,
        reason = reason.as_str(),
        "Readiness check failed: BPF map pins are not present yet"
    );
    render(
        StatusCode::SERVICE_UNAVAILABLE,
        StatusBody::with_reason(Status::NotReady, reason),
        format,
    )
}
