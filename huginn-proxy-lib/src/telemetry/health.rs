use hyper::Response;
use hyper::StatusCode;
use tracing::warn;

use crate::config::HealthFormat;
use crate::telemetry::readiness::NotReadyReason;
use crate::telemetry::status::{Status, StatusBody};
use crate::utils::http::RespBody;

/// Health check - always 200 while the process is running.
pub fn health_check_response(format: HealthFormat) -> Response<RespBody> {
    StatusBody::new(Status::Healthy).render(StatusCode::OK, format)
}

/// Liveness check - always 200 while the process is running.
pub fn live_check_response(format: HealthFormat) -> Response<RespBody> {
    StatusBody::new(Status::Alive).render(StatusCode::OK, format)
}

/// Readiness check - reports whether the proxy has finished starting up and is
/// accepting connections. `not_ready_reason` is `None` when ready; otherwise the
/// JSON `reason` (`proxy_starting`, `proxy_draining`, or `capture_*` from the gate).
pub fn ready_check_response(
    not_ready_reason: Option<NotReadyReason>,
    format: HealthFormat,
) -> Response<RespBody> {
    let Some(reason) = not_ready_reason else {
        return StatusBody::new(Status::Serving).render(StatusCode::OK, format);
    };

    warn!(reason = reason.as_str(), "Readiness check failed");
    StatusBody::with_reason(Status::NotReady, reason)
        .render(StatusCode::SERVICE_UNAVAILABLE, format)
}
