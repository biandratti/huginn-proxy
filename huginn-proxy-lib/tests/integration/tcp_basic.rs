#![forbid(unsafe_code)]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use huginn_proxy_lib::config::{Backend, Config, Mode, Telemetry, Timeouts};
use huginn_proxy_lib::tcp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

fn pick_free_port() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn spawn_echo_server() -> SocketAddr {
    let addr = pick_free_port();
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                match s.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                    _ => {}
                }
            });
        }
    });
    // Give the server a moment to bind.
    sleep(Duration::from_millis(50)).await;
    addr
}

fn make_config(listen: SocketAddr, backend: SocketAddr) -> Config {
    Config {
        listen,
        backends: vec![Backend {
            address: backend.to_string(),
            weight: None,
        }],
        mode: Mode::Forward,
        peek_http: false,
        timeouts: Timeouts {
            connect_ms: 1_000,
            idle_ms: 5_000,
        },
        telemetry: Telemetry {
            access_log: false,
            basic_metrics: false,
        },
        tls: None,
    }
}

#[tokio::test]
async fn tcp_forward_echo() {
    let backend_addr = spawn_echo_server().await;
    let listen_addr = pick_free_port();
    let cfg = Arc::new(make_config(listen_addr, backend_addr));

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        async move { tcp::run(cfg).await }
    });

    // Give the proxy a moment to bind.
    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(listen_addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    proxy.abort();
}

