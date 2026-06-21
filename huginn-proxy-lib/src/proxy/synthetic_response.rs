use crate::error::{ProxyError, ProxyResult};
use crate::utils::http::{empty_body, RespBody};
use http::StatusCode;
use hyper::Response;

/// Build HTTP response with status code of 4xx and 5xx
pub(crate) fn synthetic_error_response(status_code: StatusCode) -> ProxyResult<Response<RespBody>> {
    let res = Response::builder()
        .status(status_code)
        .body(empty_body())
        .map_err(|e| ProxyError::Http(format!("Failed to build error response: {e}")))?;
    Ok(res)
}
