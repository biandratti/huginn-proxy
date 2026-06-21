use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Response, StatusCode};
use serde::Serialize;

pub(crate) type RespBody = BoxBody<Bytes, hyper::Error>;

pub(crate) fn full_body(bytes: impl Into<Bytes>) -> RespBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

pub(crate) fn json_response(status: StatusCode, body: impl Serialize) -> Response<RespBody> {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(full_body(bytes));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}
