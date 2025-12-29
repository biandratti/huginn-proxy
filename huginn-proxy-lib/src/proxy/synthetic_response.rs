use crate::error::{ProxyError, ProxyResult};
use http::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::Response;

type RespBody = BoxBody<Bytes, hyper::Error>;

/// Build HTTP response with status code of 4xx and 5xx
pub(crate) fn synthetic_error_response(status_code: StatusCode) -> ProxyResult<Response<RespBody>> {
    let res = Response::builder()
        .status(status_code)
        .body(empty_body())
        .map_err(|e| ProxyError::Http(format!("Failed to build error response: {e}")))?;
    Ok(res)
}

fn empty_body() -> RespBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}
