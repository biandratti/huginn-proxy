use std::convert::Infallible;

use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Serialize)]
struct Resp<'a> {
    message: &'a str,
    protocol: &'a str,
    path: &'a str,
    headers: serde_json::Value,
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let mut headers_json = serde_json::Map::new();
    for (k, v) in req.headers().iter() {
        let val = v.to_str().unwrap_or_default().to_string();
        headers_json.insert(k.as_str().to_string(), json!(val));
    }
    let headers_json = serde_json::Value::Object(headers_json);

    let payload = Resp {
        message: "HTTP/2 backend",
        protocol: "HTTP/2",
        path: req.uri().path(),
        headers: headers_json,
    };

    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Full::new(body.into()));
    *resp.status_mut() = StatusCode::OK;
    if let Ok(content_type) = "application/json".parse() {
        resp.headers_mut()
            .insert(hyper::header::CONTENT_TYPE, content_type);
    }
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt().with_target(false).init();

    let addr = "0.0.0.0:9000";
    let listener = TcpListener::bind(addr).await?;
    info!("HTTP/2 server listening on {}", addr);

    let builder = ConnBuilder::new(hyper_util::rt::TokioExecutor::new()).http2_only();

    loop {
        let (stream, peer) = listener.accept().await?;
        let svc = service_fn(handle);
        let builder = builder.clone();
        tokio::spawn(async move {
            if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                tracing::warn!(?peer, error = %e, "serve_connection error");
            }
        });
    }
}
