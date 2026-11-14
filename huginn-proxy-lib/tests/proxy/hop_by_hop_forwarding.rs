use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::hot_reload::helpers::{free_port, spawn_proxy, toml_single_backend, write_toml};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), BoxError>;

/// Backend that echoes one `name: value` line per request header plus `body-len: N`, and
/// sets `Connection: x-internal-debug`, `X-Internal-Debug`, `Keep-Alive` and
/// `Proxy-Authenticate` on its response.
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
                    let (parts, body) = req.into_parts();
                    let mut echo = String::new();
                    for (name, value) in &parts.headers {
                        echo.push_str(&format!("{name}: {}\n", value.to_str().unwrap_or("?")));
                    }
                    let body_len = body.collect().await.map_or(0, |b| b.to_bytes().len());
                    echo.push_str(&format!("body-len: {body_len}\n"));
                    let resp = Response::builder()
                        .header("connection", "x-internal-debug")
                        .header("x-internal-debug", "1")
                        .header("keep-alive", "timeout=5")
                        .header("proxy-authenticate", "Basic realm=\"backend\"")
                        .header("x-backend", "kept")
                        .body(Full::new(Bytes::from(echo)))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                    Ok::<_, Infallible>(resp)
                });
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Ok((addr, handle.abort_handle()))
}

/// Send a raw HTTP/1.1 request (`head` is the header block after the request line, `body`
/// the bytes after the blank line) and return the lowercased response head and the body.
///
/// `head` must make the proxy close the connection (`Connection: close`), since the
/// response is read to EOF.
async fn raw_exchange(head: &str, body: &str) -> Result<(String, String), BoxError> {
    let (backend, _backend_handle) = spawn_echo_backend().await?;
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;
    write_toml(tmp.path(), &toml_single_backend(free_port()?, backend))?;
    let (proxy, _proxy_handle) = spawn_proxy(tmp.path(), false, 0).await?;

    let mut stream = TcpStream::connect(proxy).await?;
    let request = format!("POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n{head}\r\n{body}");
    stream.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (resp_head, resp_body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("malformed response: {text}"))?;
    Ok((resp_head.to_ascii_lowercase(), resp_body.to_string()))
}

/// Whether the backend echo in `body` has a request header line named `name`.
fn backend_got(body: &str, name: &str) -> bool {
    body.lines()
        .any(|line| line.split_once(':').is_some_and(|(n, _)| n.trim() == name))
}

#[tokio::test]
async fn request_hop_by_hop_headers_do_not_reach_backend() -> TestResult {
    let head = "Connection: close, x-custom\r\n\
                X-Custom: v\r\n\
                Keep-Alive: timeout=9\r\n\
                Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\
                Upgrade: websocket\r\n\
                X-End-To-End: kept\r\n\
                Content-Length: 0\r\n";
    let (resp_head, body) = raw_exchange(head, "").await?;
    assert!(resp_head.starts_with("http/1.1 200"), "{resp_head}");
    for name in ["x-custom", "keep-alive", "proxy-authorization", "upgrade"] {
        assert!(!backend_got(&body, name), "{name} must not reach the backend:\n{body}");
    }
    assert!(
        !body.contains("x-custom"),
        "Connection must not carry the client's list:\n{body}"
    );
    assert!(body.contains("x-end-to-end: kept"), "end-to-end headers must pass:\n{body}");
    Ok(())
}

#[tokio::test]
async fn connection_naming_a_fingerprint_is_reported_and_removed() -> TestResult {
    let head = "Connection: close, x-tls-ja4, x-forwarded-for\r\nContent-Length: 0\r\n";
    let (_, body) = raw_exchange(head, "").await?;
    assert!(
        body.contains("x-fingerprint-spoofing-detected: x-tls-ja4\n"),
        "naming a fingerprint header in Connection must be reported:\n{body}"
    );
    assert!(
        !body.contains("connection: close, x-tls-ja4"),
        "the client's Connection list must not reach the backend:\n{body}"
    );
    // The proxy's own X-Forwarded-For is added after the strip, so it survives.
    assert!(body.contains("x-forwarded-for: 127.0.0.1\n"), "{body}");
    Ok(())
}

#[tokio::test]
async fn connection_naming_only_forwarded_headers_is_not_reported() -> TestResult {
    let head = "Connection: close, x-forwarded-for\r\nContent-Length: 0\r\n";
    let (_, body) = raw_exchange(head, "").await?;
    assert!(!backend_got(&body, "x-fingerprint-spoofing-detected"), "{body}");
    assert!(body.contains("x-forwarded-for: 127.0.0.1\n"), "{body}");
    Ok(())
}

#[tokio::test]
async fn te_trailers_is_kept_and_other_codings_dropped() -> TestResult {
    let head = "Connection: close, te\r\nTE: trailers, deflate\r\nContent-Length: 0\r\n";
    let (_, body) = raw_exchange(head, "").await?;
    assert!(body.contains("te: trailers\n"), "{body}");
    Ok(())
}

#[tokio::test]
async fn chunked_request_body_still_reaches_backend() -> TestResult {
    // Transfer-Encoding is stripped from the forwarded headers; the body must still arrive.
    let head = "Connection: close\r\nTransfer-Encoding: chunked\r\n";
    let (resp_head, body) = raw_exchange(head, "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").await?;
    assert!(resp_head.starts_with("http/1.1 200"), "{resp_head}");
    assert!(body.contains("body-len: 11\n"), "{body}");
    Ok(())
}

#[tokio::test]
async fn response_hop_by_hop_headers_do_not_reach_client() -> TestResult {
    let (resp_head, body) = raw_exchange("Connection: close\r\nContent-Length: 0\r\n", "").await?;
    for name in ["x-internal-debug", "keep-alive", "proxy-authenticate"] {
        assert!(
            !resp_head.contains(&format!("\r\n{name}:")),
            "{name} from the backend must not reach the client:\n{resp_head}"
        );
    }
    assert!(resp_head.contains("\r\nx-backend: kept"), "{resp_head}");
    assert!(body.contains("body-len: 0\n"), "response body must be intact: {body}");
    Ok(())
}
