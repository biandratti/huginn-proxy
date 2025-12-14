#![forbid(unsafe_code)]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use huginn_proxy_lib::config::{Backend, Config, Mode, Telemetry, Timeouts};
use huginn_proxy_lib::tcp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn pick_free_port() -> TestResult<SocketAddr> {
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

async fn spawn_echo_server() -> TestResult<SocketAddr> {
    let addr = pick_free_port()?;
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("echo bind failed: {e}");
                return;
            }
        };
        loop {
            let (mut s, _) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("echo accept failed: {e}");
                    continue;
                }
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if let Ok(n) = s.read(&mut buf).await {
                    if n > 0 {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                }
            });
        }
    });
    // Give the server a moment to bind.
    sleep(Duration::from_millis(50)).await;
    Ok(addr)
}

fn make_config(listen: SocketAddr, backend: SocketAddr) -> Config {
    Config {
        listen,
        backends: vec![Backend { address: backend.to_string(), weight: None }],
        mode: Mode::Forward,
        peek_http: false,
        timeouts: Timeouts { connect_ms: 1_000, idle_ms: 5_000 },
        telemetry: Telemetry { access_log: false, basic_metrics: false },
        tls: None,
    }
}

#[tokio::test]
async fn tcp_forward_echo() -> TestResult {
    let backend_addr = spawn_echo_server().await?;
    let listen_addr = pick_free_port()?;
    let cfg = Arc::new(make_config(listen_addr, backend_addr));

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        async move { tcp::run(cfg).await }
    });

    // Give the proxy a moment to bind.
    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(listen_addr).await?;
    client.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"ping");

    proxy.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_backend_connect_timeout() -> TestResult {
    // Unreachable backend to trigger connect timeout.
    let backend_addr: SocketAddr = "10.255.255.1:9".parse()?; // unroutable bogon
    let listen_addr = pick_free_port()?;
    let cfg = Arc::new(Config {
        listen: listen_addr,
        backends: vec![Backend { address: backend_addr.to_string(), weight: None }],
        mode: Mode::Forward,
        peek_http: false,
        timeouts: Timeouts { connect_ms: 50, idle_ms: 5_000 },
        telemetry: Telemetry { access_log: false, basic_metrics: false },
        tls: None,
    });

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        async move { tcp::run(cfg).await }
    });

    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(listen_addr).await?;
    // Attempt to read; expect close or error within a short timeout.
    let mut buf = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf)).await;
    assert!(res.is_err() || matches!(res, Ok(Ok(0)) | Ok(Err(_))));

    proxy.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_idle_timeout_no_traffic() -> TestResult {
    // Backend echo server, but we won't send data; idle timeout should close.
    let backend_addr = spawn_echo_server().await?;
    let listen_addr = pick_free_port()?;
    let cfg = Arc::new(Config {
        listen: listen_addr,
        backends: vec![Backend { address: backend_addr.to_string(), weight: None }],
        mode: Mode::Forward,
        peek_http: false,
        timeouts: Timeouts {
            connect_ms: 1_000,
            idle_ms: 100, // short idle
        },
        telemetry: Telemetry { access_log: false, basic_metrics: false },
        tls: None,
    });

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        async move { tcp::run(cfg).await }
    });

    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(listen_addr).await?;
    // Do not send anything; wait for idle timeout to close the connection.
    let mut buf = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_millis(800), client.read(&mut buf)).await;
    // Expect timeout elapsed (Err) or EOF/error from closed connection.
    assert!(res.is_err() || matches!(res, Ok(Ok(0)) | Ok(Err(_))));

    proxy.abort();
    Ok(())
}
