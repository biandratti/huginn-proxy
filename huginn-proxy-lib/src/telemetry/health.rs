use hyper::Response;
use hyper::StatusCode;
use tracing::warn;

use crate::config::HealthFormat;
use crate::telemetry::readiness::NotReadyReason;
use crate::telemetry::status::{Status, StatusBody};
use crate::utils::http::{json_response, text_response, RespBody};

pub(crate) fn render(
    http_status: StatusCode,
    body: StatusBody,
    format: HealthFormat,
) -> Response<RespBody> {
    match format {
        HealthFormat::Json => json_response(http_status, body),
        HealthFormat::Text => text_response(http_status, body.proxy_text_token()),
    }
}

/// Health check - always 200 while the process is running.
pub fn health_check_response(format: HealthFormat) -> Response<RespBody> {
    render(StatusCode::OK, StatusBody::new(Status::Healthy), format)
}

/// Liveness check - always 200 while the process is running.
pub fn live_check_response(format: HealthFormat) -> Response<RespBody> {
    render(StatusCode::OK, StatusBody::new(Status::Alive), format)
}

/// Readiness check - reports whether the proxy has finished starting up and is
/// accepting connections.
/// `not_ready_reason` is `None` when ready; otherwise the JSON `reason`
/// (`proxy_starting` or `proxy_draining`).
pub fn ready_check_response(
    not_ready_reason: Option<NotReadyReason>,
    format: HealthFormat,
) -> Response<RespBody> {
    let Some(reason) = not_ready_reason else {
        return render(StatusCode::OK, StatusBody::new(Status::Serving), format);
    };

    warn!(reason = reason.as_str(), "Readiness check failed");
    render(
        StatusCode::SERVICE_UNAVAILABLE,
        StatusBody::with_reason(Status::NotReady, reason),
        format,
    )
}
