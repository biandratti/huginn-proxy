use hyper::{Response, StatusCode};
use prometheus::Registry;
use tracing::{debug, warn};

use crate::config::HealthFormat;
use crate::telemetry::health::render;
use crate::telemetry::status::{Status, StatusBody};
use crate::telemetry::{
    handle_metrics, health_check_response, live_check_response, ready_check_response, Readiness,
};
use crate::utils::http::RespBody;

pub fn dispatch(
    path: &str,
    registry: &Registry,
    readiness: &Readiness,
    format: HealthFormat,
) -> Response<RespBody> {
    let response = match path {
        "/health" => health_check_response(format),
        "/ready" => ready_check_response(readiness.not_ready_reason(), format),
        "/live" => live_check_response(format),
        "/metrics" => handle_metrics(registry).unwrap_or_else(|e| {
            warn!(error = %e, "Failed to encode metrics");
            render(StatusCode::INTERNAL_SERVER_ERROR, StatusBody::new(Status::Error), format)
        }),
        _ => render(StatusCode::NOT_FOUND, StatusBody::new(Status::NotFound), format),
    };

    debug!(path, status = response.status().as_u16(), "Observability request handled");
    response
}
