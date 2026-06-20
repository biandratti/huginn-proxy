//! Shared helpers for building boxed HTTP response bodies and JSON responses.
//!
//! Centralises the `BoxBody<Bytes, hyper::Error>` alias and the `Full` boxing dance
//! (`Full` is infallible, so its `Infallible` error is mapped away) that would otherwise
//! be duplicated across the observability handlers.

use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Response, StatusCode};
use serde::Serialize;

/// Boxed response body used by the observability server.
pub(crate) type RespBody = BoxBody<Bytes, hyper::Error>;

/// Box a fixed byte buffer into a [`RespBody`].
pub(crate) fn full_body(bytes: impl Into<Bytes>) -> RespBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Build an `application/json` response with the given status.
pub(crate) fn json_response(status: StatusCode, body: impl Serialize) -> Response<RespBody> {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(full_body(bytes));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}
