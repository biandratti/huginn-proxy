#![forbid(unsafe_code)]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use huginn_proxy_lib::config::{Backend, Config, LoadBalance, Mode, Telemetry, Timeouts};
use huginn_proxy_lib::tcp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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
            Err(_) => return,
        };
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                continue;
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
        balancing: LoadBalance::None,
        peek_http: false,
        timeouts: Timeouts { connect_ms: 1_000, idle_ms: 5_000 },
        telemetry: Telemetry { access_log: false, basic_metrics: false },
        tls: None,
        max_connections: None,
        backlog: None,
    }
}

#[tokio::test]
async fn tcp_forward_echo() -> TestResult<()> {
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
async fn tcp_backend_down() -> TestResult<()> {
    // No backend server started on backend_addr
    let backend_addr = pick_free_port()?;
    let listen_addr = pick_free_port()?;
    let cfg = Arc::new(make_config(listen_addr, backend_addr));

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        async move { tcp::run(cfg).await }
    });

    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(listen_addr).await?;
    // Write may be accepted locally; subsequent read should fail/EOF once connect to backend fails.
    client.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    let read_res = client.read(&mut buf).await;
    assert!(read_res.is_err() || matches!(read_res, Ok(0)));

    proxy.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_connection_limit() -> TestResult<()> {
    let backend_addr = spawn_echo_server().await?;
    let listen_addr = pick_free_port()?;
    let mut cfg = make_config(listen_addr, backend_addr);
    cfg.max_connections = Some(1);
    let cfg = Arc::new(cfg);

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        async move { tcp::run(cfg).await }
    });

    sleep(Duration::from_millis(50)).await;

    // First client holds the slot
    let mut c1 = TcpStream::connect(listen_addr).await?;
    c1.write_all(b"ping").await?;

    // Second client should be dropped due to limit; writing should fail
    let mut c2 = TcpStream::connect(listen_addr).await?;
    c2.write_all(b"ping").await?;
    let mut buf = [0u8; 4];
    let res = c2.read(&mut buf).await;
    assert!(res.is_err() || matches!(res, Ok(0)));

    proxy.abort();
    Ok(())
}
