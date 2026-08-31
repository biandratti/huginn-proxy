use hyper::Response;
use hyper::StatusCode;
use tracing::warn;

use crate::telemetry::status::{Status, StatusBody};
use crate::utils::http::{json_response, RespBody};

/// Health check - always 200 while the process is running.
pub fn health_check_response() -> Response<RespBody> {
    json_response(StatusCode::OK, StatusBody::new(Status::Healthy))
}

/// Liveness check - always 200 while the process is running.
pub fn live_check_response() -> Response<RespBody> {
    json_response(StatusCode::OK, StatusBody::new(Status::Alive))
}

/// Readiness check - reports whether the proxy has finished starting up and is
/// accepting connections.
/// `not_ready_reason` is `None` when ready; otherwise the JSON `reason`
/// (`proxy_starting` or `proxy_draining`).
pub fn ready_check_response(not_ready_reason: Option<&'static str>) -> Response<RespBody> {
    let Some(reason) = not_ready_reason else {
        return json_response(StatusCode::OK, StatusBody::new(Status::Ready));
    };

    warn!(reason, "Readiness check failed");
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        StatusBody::with_reason(Status::NotReady, reason),
    )
}
