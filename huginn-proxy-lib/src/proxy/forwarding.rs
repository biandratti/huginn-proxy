use http::{Request, Response};
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;

use crate::error::Result;

type HttpClient = Client<HttpConnector, Incoming>;
type RespBody = BoxBody<bytes::Bytes, hyper::Error>;

pub async fn forward(
    req: Request<Incoming>,
    client: HttpClient,
    backend: String,
) -> Result<Response<RespBody>> {
    let uri = format!(
        "http://{}{}",
        backend,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("")
    )
    .parse()
    .map_err(crate::error::ProxyError::InvalidUri)?;

    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    let out_req = Request::from_parts(parts, body);
    let resp = client
        .request(out_req)
        .await
        .map_err(|e| crate::error::ProxyError::Http(format!("Request failed: {e}")))?;
    Ok(resp.map(|b| b.boxed()))
}

pub fn empty_body() -> RespBody {
    use http_body_util::Full;
    Full::new(bytes::Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

pub fn bad_gateway() -> Response<RespBody> {
    use http::Response;
    use http::StatusCode;
    let mut resp = Response::new(empty_body());
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    resp
}

pub fn pick_route<'a>(path: &str, routes: &'a [crate::config::Route]) -> Option<&'a str> {
    routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
        .map(|r| r.backend.as_str())
}
