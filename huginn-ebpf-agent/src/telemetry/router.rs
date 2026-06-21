use crate::telemetry::http::{json_response, RespBody};
use crate::telemetry::status::{Status, StatusBody};
use crate::telemetry::{health, metrics_handler};
use hyper::{Response, StatusCode};
use prometheus::Registry;
use tracing::{debug, warn};

/// Route an observability request. Health endpoints are infallible; metrics may fail to
/// encode and falls back to a JSON 500. Unknown paths return a JSON 404.
///
/// Every request is traced at `debug` (path + resulting status); failures that aren't
/// otherwise visible (not-ready reason, metrics encode error) are logged at `warn` by the
/// handlers themselves so the cause shows up even at the default log level.
pub fn dispatch(path: &str, registry: &Registry, pin_path: &str) -> Response<RespBody> {
    let response = match path {
        "/metrics" => metrics_handler::handle_metrics(registry).unwrap_or_else(|e| {
            warn!(error = %e, "Failed to encode metrics");
            json_response(StatusCode::INTERNAL_SERVER_ERROR, StatusBody::new(Status::Error))
        }),
        "/health" => health::health_check_response(),
        "/ready" => health::ready_check_response(pin_path),
        "/live" => health::live_check_response(),
        _ => json_response(StatusCode::NOT_FOUND, StatusBody::new(Status::NotFound)),
    };

    debug!(path, status = response.status().as_u16(), "Observability request handled");
    response
}
