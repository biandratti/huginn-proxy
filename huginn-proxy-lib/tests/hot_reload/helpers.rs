use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;

use huginn_proxy_lib::{config::load_from_path, Metrics, WatchOptions};

/// Grab an ephemeral port then release it so the proxy (or backend) can bind
/// to it immediately after. There is a small TOCTOU window, acceptable in
/// unit tests running on loopback.
pub fn free_port() -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Starts a simple HTTP/1.1 backend that always returns 200 OK with an
/// `x-backend: {identity}` header so callers can distinguish which backend
/// answered.
///
/// Returns the bound address and a handle to abort the server task.
pub async fn spawn_mock_backend(
    identity: &'static str,
) -> Result<(SocketAddr, tokio::task::AbortHandle), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
                    let id = identity;
                    async move {
                        let resp = Response::builder()
                            .status(200)
                            .header("x-backend", id)
                            .body(Full::new(Bytes::from("ok")))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    Ok((addr, handle.abort_handle()))
}

/// Minimal valid TOML with a single backend routed at `/`.
pub fn toml_single_backend(listen_port: u16, backend: SocketAddr) -> String {
    format!(
        r#"listen = {{ addrs = ["127.0.0.1:{listen_port}"] }}
backends = [{{ address = "{backend}" }}]
routes = [{{ prefix = "/", backend = "{backend}" }}]
"#
    )
}

/// TOML with multiple backends and an explicit route table.
///
/// `routes` is a slice of `(prefix, backend_addr)` pairs.
pub fn toml_with_routes(
    listen_port: u16,
    backends: &[SocketAddr],
    routes: &[(&str, SocketAddr)],
) -> String {
    let be: Vec<String> = backends
        .iter()
        .map(|a| format!("{{ address = \"{a}\" }}"))
        .collect();
    let rt: Vec<String> = routes
        .iter()
        .map(|(prefix, backend)| format!("{{ prefix = \"{prefix}\", backend = \"{backend}\" }}"))
        .collect();

    format!(
        "listen = {{ addrs = [\"127.0.0.1:{listen_port}\"] }}\nbackends = [{}]\nroutes = [{}]\n",
        be.join(", "),
        rt.join(", ")
    )
}

/// TOML that enables a very tight global rate limit (1 req / 60 s, burst 1).
pub fn toml_with_rate_limit(listen_port: u16, backend: SocketAddr) -> String {
    format!(
        r#"listen = {{ addrs = ["127.0.0.1:{listen_port}"] }}
backends = [{{ address = "{backend}" }}]
routes = [{{ prefix = "/", backend = "{backend}" }}]

[security.rate_limit]
enabled = true
requests_per_second = 1
burst = 1
window_seconds = 60
"#
    )
}

/// Write `content` to `path`.
pub fn write_toml(
    path: &Path,
    content: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    std::fs::write(path, content)?;
    Ok(())
}

/// Parse the TOML at `config_path`, start the proxy, and wait for it to
/// accept TCP connections. Returns `(listen_addr, abort_handle)`.
pub async fn spawn_proxy(
    config_path: &Path,
    watch: bool,
    watch_delay_secs: u32,
) -> Result<(SocketAddr, tokio::task::AbortHandle), Box<dyn std::error::Error + Send + Sync>> {
    let config = load_from_path(config_path)?;
    let listen_addr = config.listen.addrs[0];

    let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
    let static_cfg = Arc::new(static_cfg);
    let dynamic_cfg = Arc::new(ArcSwap::from_pointee(dynamic_cfg));

    let config_path_buf = config_path.to_path_buf();
    let handle = tokio::spawn(async move {
        let _ = huginn_proxy_lib::run(
            static_cfg,
            dynamic_cfg,
            Metrics::new_noop(),
            None,
            WatchOptions { config_path: Some(config_path_buf), watch, watch_delay_secs },
        )
        .await;
    });

    wait_for_ready(listen_addr).await?;
    Ok((listen_addr, handle.abort_handle()))
}

/// Poll until the proxy accepts a TCP connection or the 10-second deadline expires.
pub async fn wait_for_ready(
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(30)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("proxy at {addr} did not become ready within 10 s").into())
}

/// Send an HTTP GET to `http://{addr}{path}` and return `(status, x-backend header)`.
pub async fn http_get(
    addr: SocketAddr,
    path: &str,
) -> Result<(u16, Option<String>), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client.get(format!("http://{addr}{path}")).send().await?;

    let status = resp.status().as_u16();
    let backend = resp
        .headers()
        .get("x-backend")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    Ok((status, backend))
}

/// Wait until `http_get` returns the expected backend identity, up to
/// `timeout_secs` seconds. Fails the test if not met in time.
pub async fn wait_for_backend(
    addr: SocketAddr,
    path: &str,
    expected_backend: &str,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected = expected_backend.to_string();
    tokio::time::timeout(Duration::from_secs(timeout_secs), async move {
        loop {
            if let Ok((200, Some(ref b))) = http_get(addr, path).await {
                if b == &expected {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| {
        format!("backend did not switch to {expected_backend} within {timeout_secs}s").into()
    })
}

/// Send SIGHUP to the current process.
///
/// Uses the C-library `kill(getpid(), SIGHUP)` directly rather than spawning
/// an external subprocess, which avoids permission issues in sandboxed
/// environments where forking a `kill(1)` process is restricted.
///
/// Returns `true` if the signal was delivered successfully.
#[cfg(unix)]
pub fn send_sighup() -> bool {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let ret = unsafe { kill(std::process::id() as i32, 1) }; // SIGHUP = 1
    ret == 0
}
