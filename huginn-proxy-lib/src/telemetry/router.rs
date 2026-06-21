use hyper::{Response, StatusCode};
use prometheus::Registry;
use tracing::{debug, warn};

use crate::telemetry::status::{Status, StatusBody};
use crate::telemetry::{
    handle_metrics, health_check_response, live_check_response, ready_check_response, Readiness,
};
use crate::utils::http::{json_response, RespBody};

pub fn dispatch(path: &str, registry: &Registry, readiness: &Readiness) -> Response<RespBody> {
    let response = match path {
        "/health" => health_check_response(),
        "/ready" => ready_check_response(readiness.is_ready()),
        "/live" => live_check_response(),
        "/metrics" => handle_metrics(registry).unwrap_or_else(|e| {
            warn!(error = %e, "Failed to encode metrics");
            json_response(StatusCode::INTERNAL_SERVER_ERROR, StatusBody::new(Status::Error))
        }),
        _ => json_response(StatusCode::NOT_FOUND, StatusBody::new(Status::NotFound)),
    };

    debug!(path, status = response.status().as_u16(), "Observability request handled");
    response
}
