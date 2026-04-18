//! Integration tests for h2c (HTTP/2 cleartext) backend forwarding.
//!
//! These tests cover the `http_version: http2` / `http_version: preserve` code paths
//! at the network level.  They cannot be exercised by the e2e suite because the
//! external backend image (traefik/whoami) does not support h2c.
//!
//! Architecture of each test:
//!   [h2c client (same config as ClientPool::http2)]
//!       → TCP cleartext →
//!   [in-process hyper h2 server]

use bytes::Bytes;
use http::{Request, Response, StatusCode, Uri, Version};
use http_body_util::Empty;
use huginn_proxy_lib::config::{Backend, BackendHttpVersion};
use huginn_proxy_lib::proxy::forwarding::determine_http_version;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::net::TcpListener;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Build an h2c-only client — identical settings to `ClientPool::create_http2_client`.
fn make_h2c_client() -> Client<HttpConnector, Empty<Bytes>> {
    let connector = HttpConnector::new();
    let mut builder = Client::builder(TokioExecutor::new());
    builder.http2_only(true);
    builder.build(connector)
}

async fn spawn_h2c_server(flag: Arc<AtomicBool>) -> Result<std::net::SocketAddr, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let io = TokioIo::new(stream);

        let svc = service_fn(move |req: Request<Incoming>| {
            flag.store(req.version() == Version::HTTP_2, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new())) }
        });

        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await
            .ok();
    });

    Ok(addr)
}

#[tokio::test]
async fn test_h2c_client_sends_http2_to_backend() -> Result<(), BoxError> {
    let flag = Arc::new(AtomicBool::new(false));
    let addr = spawn_h2c_server(flag.clone()).await?;

    let client = make_h2c_client();
    let uri: Uri = format!("http://{addr}/").parse()?;
    let req = Request::builder()
        .version(Version::HTTP_2)
        .uri(uri)
        .body(Empty::<Bytes>::new())?;

    let resp = client.request(req).await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        flag.load(Ordering::SeqCst),
        "backend should have received an HTTP/2 request over cleartext (h2c)"
    );
    Ok(())
}

#[tokio::test]
async fn test_h2c_multiplexing_multiple_requests() -> Result<(), BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counter_clone = counter.clone();

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let io = TokioIo::new(stream);
        let svc = service_fn(move |_req: Request<Incoming>| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            async move { Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new())) }
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await
            .ok();
    });

    let client = make_h2c_client();

    for _ in 0_u8..3 {
        let uri: Uri = format!("http://{addr}/").parse()?;
        let req = Request::builder()
            .version(Version::HTTP_2)
            .uri(uri)
            .body(Empty::<Bytes>::new())?;
        let resp = client.request(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    assert_eq!(counter.load(Ordering::SeqCst), 3, "server should have received all 3 requests");
    Ok(())
}

#[test]
fn test_preserve_forwards_http2_as_h2c() {
    let backend = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Preserve),
    };

    assert_eq!(
        determine_http_version(Some(&backend), Version::HTTP_2, false),
        Version::HTTP_2,
        "preserve mode must pass HTTP/2 through as h2c (no TLS on backend leg)"
    );
}

#[test]
fn test_preserve_forwards_http11_as_http11() {
    let backend = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Preserve),
    };

    assert_eq!(
        determine_http_version(Some(&backend), Version::HTTP_11, false),
        Version::HTTP_11,
        "preserve mode must pass HTTP/1.1 through unchanged"
    );
}

#[test]
fn test_forced_http2_config_always_uses_h2c() {
    let backend = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Http2),
    };

    assert_eq!(
        determine_http_version(Some(&backend), Version::HTTP_11, false),
        Version::HTTP_2,
        "forced http2 must use h2c even when client used HTTP/1.1"
    );
    assert_eq!(
        determine_http_version(Some(&backend), Version::HTTP_2, false),
        Version::HTTP_2,
        "forced http2 must use h2c when client also used HTTP/2"
    );
}

#[test]
fn test_forced_http11_config_always_uses_http11() {
    let backend = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Http11),
    };

    assert_eq!(
        determine_http_version(Some(&backend), Version::HTTP_2, false),
        Version::HTTP_11,
        "forced http11 must downgrade h2 to HTTP/1.1"
    );
    assert_eq!(
        determine_http_version(Some(&backend), Version::HTTP_11, false),
        Version::HTTP_11,
        "forced http11 must keep HTTP/1.1"
    );
}
