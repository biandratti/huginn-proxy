//! E2E: PROXY protocol v2.
//!
//! Drives the full accept loop (in-process proxy + mock backend over plain HTTP) and asserts that
//! a v2 header from a **trusted** peer makes the proxy recover the client's `(src_ip, src_port)`
//! and reflect it in `X-Forwarded-For` / `X-Forwarded-Port`. Also covers auto-detection (no header
//! → direct client) and the `require` + untrusted-peer drop.
//!
//! Plain HTTP is used so the test client can prepend the header before the request without a TLS
//! handshake; byte-alignment with the following ClientHello is already proven by the parser unit
//! test `consumes_exactly_header_leaving_clienthello`.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::{Metrics, WatchOptions};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// 12-byte PROXY v2 signature: `\r\n\r\n\0\r\nQUIT\n`.
const V2_SIGNATURE: [u8; 12] =
    [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

/// Build a PROXY protocol v2 header for an IPv4 TCP `(src, dst)` pair.
fn proxy_v2_ipv4(src: SocketAddrV4, dst: SocketAddrV4) -> Vec<u8> {
    let mut buf = Vec::with_capacity(28);
    buf.extend_from_slice(&V2_SIGNATURE);
    buf.push((2 << 4) | 0x1); // version 2, command PROXY
    buf.push((0x1 << 4) | 0x1); // AF_INET, STREAM
    buf.extend_from_slice(&12u16.to_be_bytes()); // address block length
    buf.extend_from_slice(&src.ip().octets());
    buf.extend_from_slice(&dst.ip().octets());
    buf.extend_from_slice(&src.port().to_be_bytes());
    buf.extend_from_slice(&dst.port().to_be_bytes());
    buf
}

/// Backend that echoes the `X-Forwarded-For` / `X-Forwarded-Port` it received into the body.
async fn spawn_echo_backend(
) -> Result<(SocketAddr, tokio::task::AbortHandle), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc =
                    service_fn(move |req: hyper::Request<hyper::body::Incoming>| async move {
                        let xff = req
                            .headers()
                            .get("x-forwarded-for")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("(none)")
                            .to_string();
                        let xfp = req
                            .headers()
                            .get("x-forwarded-port")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("(none)")
                            .to_string();
                        let body = format!("xff={xff};xfp={xfp}");
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

fn free_port() -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Spawn the proxy from a TOML config and wait until it accepts connections.
async fn spawn_proxy(
    toml: &str,
) -> Result<(SocketAddr, tokio::task::AbortHandle), Box<dyn std::error::Error + Send + Sync>> {
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;
    std::fs::write(tmp.path(), toml)?;

    let config = load_from_path(tmp.path())?;
    let listen_addr = config.listen.addrs[0];

    let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
    let static_cfg = Arc::new(static_cfg);
    let dynamic_cfg = Arc::new(ArcSwap::from_pointee(dynamic_cfg));

    let handle = tokio::spawn(async move {
        let (shutdown_tx, _) = huginn_proxy_lib::shutdown_channel();
        let _ = huginn_proxy_lib::run(
            static_cfg,
            dynamic_cfg,
            Metrics::new_noop(),
            None,
            WatchOptions::default(),
            shutdown_tx,
            huginn_proxy_lib::Readiness::new(),
        )
        .await;
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(listen_addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(30)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("proxy at {listen_addr} did not become ready"))?;

    // `tmp` must outlive the proxy task (it reads the file at startup); leak it so the file stays.
    std::mem::forget(tmp);
    Ok((listen_addr, handle.abort_handle()))
}

/// Open a raw connection, optionally prepend `header_prefix`, send one plain HTTP/1.1 request,
/// and return the full response text (empty string if the peer dropped us without replying).
async fn raw_request(proxy: SocketAddr, header_prefix: &[u8]) -> String {
    let mut stream = match TcpStream::connect(proxy).await {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    if !header_prefix.is_empty() && stream.write_all(header_prefix).await.is_err() {
        return String::new();
    }
    let req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if stream.write_all(req).await.is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    // A dropped connection surfaces as either EOF (empty) or a reset error; both mean "no reply".
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn config_toml(listen_port: u16, backend: SocketAddr, mode: &str, trusted: &str) -> String {
    format!(
        r#"listen = {{ addrs = ["127.0.0.1:{listen_port}"], proxy_protocol = "{mode}" }}
backends = [{{ address = "{backend}" }}]

[security]
trusted_proxies = [{trusted}]

[[domains]]
host = "127.0.0.1"
routes = [{{ prefix = "/", backend = "{backend}" }}]
"#
    )
}

#[tokio::test]
async fn optional_trusted_peer_header_is_applied() -> TestResult {
    let (backend, _bh) = spawn_echo_backend().await?;
    let port = free_port()?;
    let (proxy, _ph) =
        spawn_proxy(&config_toml(port, backend, "optional", "\"127.0.0.1/32\", \"::1/128\""))
            .await?;

    let src = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51115);
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let header = proxy_v2_ipv4(src, dst);

    let resp = raw_request(proxy, &header).await;

    assert!(resp.contains("200"), "expected a 200 response, got: {resp}");
    assert!(
        resp.contains("xff=203.0.113.7"),
        "X-Forwarded-For should be the PROXY-declared client IP, got: {resp}"
    );
    assert!(
        resp.contains("xfp=51115"),
        "X-Forwarded-Port should be the PROXY-declared source port, got: {resp}"
    );
    Ok(())
}

#[tokio::test]
async fn optional_no_header_is_direct_client() -> TestResult {
    let (backend, _bh) = spawn_echo_backend().await?;
    let port = free_port()?;
    let (proxy, _ph) =
        spawn_proxy(&config_toml(port, backend, "optional", "\"127.0.0.1/32\"")).await?;

    // No PROXY header: auto-detection must leave the stream intact and treat us as a direct client.
    let resp = raw_request(proxy, &[]).await;

    assert!(resp.contains("200"), "expected a 200 response, got: {resp}");
    assert!(
        resp.contains("xff=127.0.0.1"),
        "without a header the client IP is the loopback socket peer, got: {resp}"
    );
    Ok(())
}

#[tokio::test]
async fn require_untrusted_peer_is_dropped() -> TestResult {
    let (backend, _bh) = spawn_echo_backend().await?;
    let port = free_port()?;
    // Trust only a non-loopback range, so the loopback test client is untrusted.
    let (proxy, _ph) =
        spawn_proxy(&config_toml(port, backend, "require", "\"192.0.2.0/24\"")).await?;

    let src = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51115);
    let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
    let header = proxy_v2_ipv4(src, dst);

    let resp = raw_request(proxy, &header).await;

    assert!(
        !resp.contains("200"),
        "require + untrusted peer must be dropped with no HTTP response, got: {resp}"
    );
    Ok(())
}
