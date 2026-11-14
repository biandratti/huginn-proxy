//! `X-Forwarded-For` sent to the backend, through the full accept loop.
//!
//! An in-process proxy (plain HTTP) forwards to a backend that echoes the `X-Forwarded-For`
//! and `Forwarded` headers it received. The loopback test client is either a direct,
//! untrusted client or, when `127.0.0.1` is in `security.trusted_proxies`, a trusted proxy.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;

use huginn_proxy_lib::fingerprinting::forwarded;

use crate::hot_reload::helpers::{free_port, spawn_proxy, write_toml};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), BoxError>;

/// Backend that answers `xff=<all X-Forwarded-For lines joined by '|'>;fwd=<Forwarded>`.
async fn spawn_echo_backend() -> Result<(SocketAddr, tokio::task::AbortHandle), BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let lines: Vec<&str> = req
                        .headers()
                        .get_all(forwarded::FOR)
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .collect();
                    let fwd = req
                        .headers()
                        .get(hyper::header::FORWARDED)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("(none)");
                    let body = format!("xff={};fwd={fwd}", lines.join("|"));
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Ok((addr, handle.abort_handle()))
}

/// Send one request with the given `X-Forwarded-For` field lines and a `Forwarded` header
/// through a proxy whose `trusted_proxies.cidrs` is `trusted`, and return the backend echo.
async fn backend_view(trusted: &str, xff_lines: &[&str]) -> Result<String, BoxError> {
    let (backend, _backend_handle) = spawn_echo_backend().await?;
    let listen_port = free_port()?;
    let toml = format!(
        r#"listen = {{ port = {listen_port}, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "{backend}" }}]

[security.trusted_proxies]
cidrs = [{trusted}]

[[domains]]
host = "127.0.0.1"
routes = [{{ prefix = "/", backend = "{backend}" }}]
"#
    );
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;
    write_toml(tmp.path(), &toml)?;
    let (proxy, _proxy_handle) = spawn_proxy(tmp.path(), false, 0).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut req = client
        .get(format!("http://{proxy}/"))
        .header("forwarded", "for=192.0.2.1");
    // Repeated `.header()` calls with one name are sent as separate field lines.
    for line in xff_lines {
        req = req.header(forwarded::FOR, *line);
    }
    let resp = req.send().await?;
    assert_eq!(resp.status().as_u16(), 200);
    Ok(resp.text().await?)
}

#[tokio::test]
async fn untrusted_client_chain_and_forwarded_are_dropped() -> TestResult {
    let body = backend_view("", &["203.0.113.5", "198.51.100.7"]).await?;
    assert_eq!(body, "xff=127.0.0.1;fwd=(none)");
    Ok(())
}

#[tokio::test]
async fn trusted_proxy_chain_is_cut_at_trust_boundary() -> TestResult {
    // The client hop 198.51.100.7 arrives on its own field line; 192.0.2.9 left of it is
    // client-supplied and must not reach the backend.
    let body = backend_view("\"127.0.0.1/32\"", &["192.0.2.9", "198.51.100.7"]).await?;
    assert_eq!(body, "xff=198.51.100.7, 127.0.0.1;fwd=for=192.0.2.1");
    Ok(())
}

#[tokio::test]
async fn trusted_proxy_unparseable_chain_fails_closed() -> TestResult {
    let body = backend_view("\"127.0.0.1/32\"", &["198.51.100.7, unknown"]).await?;
    assert_eq!(body, "xff=127.0.0.1;fwd=for=192.0.2.1");
    Ok(())
}
