//! HTTP routing for the observability server: maps a request path to the matching
//! health/metrics handler and centralises the 404 / 500 fallbacks.

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use prometheus::Registry;
use tracing::warn;

use crate::telemetry::{
    handle_metrics, health_check_response, live_check_response, ready_check_response, Readiness,
};

pub type RespBody = BoxBody<Bytes, hyper::Error>;

/// Build a plain-text response with the given status (used for 404 and 500).
fn status_response(status: StatusCode, message: &'static str) -> Response<RespBody> {
    let body = Full::new(Bytes::from(message))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp
}

/// Route an observability request, collapsing the per-endpoint 500 handling into one place.
pub fn dispatch(path: &str, registry: &Registry, readiness: &Readiness) -> Response<RespBody> {
    let result = match path {
        "/health" => health_check_response(),
        "/ready" => ready_check_response(readiness.is_ready()),
        "/live" => live_check_response(),
        "/metrics" => handle_metrics(registry),
        _ => return status_response(StatusCode::NOT_FOUND, "Not Found"),
    };

    result.unwrap_or_else(|e| {
        warn!(path, error = %e, "Observability handler failed to build response");
        status_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    })
}
