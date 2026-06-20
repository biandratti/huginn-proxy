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
///
/// Decoupled from backend availability on purpose: a proxy can serve traffic even when
/// every backend is down (that surfaces as 502s on real requests plus backend-health
/// metrics, not as readiness). Tying readiness to backends would keep the pod out of
/// rotation forever when backends are registered dynamically. This mirrors Traefik/Envoy.
///
/// `ready` is `false` while the listeners are still binding/initialising and during
/// graceful shutdown; `true` once the proxy is accepting connections.
pub fn ready_check_response(ready: bool) -> Response<RespBody> {
    if ready {
        return json_response(StatusCode::OK, StatusBody::new(Status::Ready));
    }

    let reason = "proxy_starting";
    warn!(reason, "Readiness check failed: proxy is not accepting connections yet");
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        StatusBody::with_reason(Status::NotReady, reason),
    )
}
