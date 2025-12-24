#![forbid(unsafe_code)]

use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use huginn_proxy_lib::config::types::{FingerprintConfig, HttpConfig, HttpRoute};
use huginn_proxy_lib::config::{Backend, Config, LoadBalance, Mode, Telemetry, Timeouts};
use huginn_proxy_lib::tcp;
use huginn_proxy_lib::tcp::metrics::ConnectionCount;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

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
        http: HttpConfig { routes: vec![], max_peek_bytes: HttpConfig::default_max_peek_bytes() },
        timeouts: Timeouts { connect_ms: 1_000, idle_ms: 5_000 },
        telemetry: Telemetry {
            access_log: false,
            basic_metrics: false,
            metrics_addr: None,
            log_level: None,
        },
        fingerprint: FingerprintConfig::default(),
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
        let counters = Arc::new(ConnectionCount::default());
        let (_tx, rx) = watch::channel(false);
        async move { tcp::run(cfg, counters, rx).await }
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
        let counters = Arc::new(ConnectionCount::default());
        let (_tx, rx) = watch::channel(false);
        async move { tcp::run(cfg, counters, rx).await }
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
        let counters = Arc::new(ConnectionCount::default());
        let (_tx, rx) = watch::channel(false);
        async move { tcp::run(cfg, counters, rx).await }
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

async fn spawn_recording_server() -> TestResult<(SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>)> {
    let addr = pick_free_port()?;
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(_) => return,
        };
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                continue;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                if s.read_to_end(&mut buf).await.is_ok() {
                    let _ = tx.send(buf);
                }
            });
        }
    });
    // Give the server a moment to bind.
    sleep(Duration::from_millis(50)).await;
    Ok((addr, rx))
}

fn write_temp_file(contents: &str) -> TestResult<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    file.write_all(contents.as_bytes())?;
    Ok(file)
}

fn make_self_signed_cert() -> TestResult<(NamedTempFile, NamedTempFile, CertificateDer<'static>)> {
    let cert = generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let cert_file = write_temp_file(&cert_pem)?;
    let key_file = write_temp_file(&key_pem)?;

    let cert_der = cert.cert.der().clone();
    Ok((cert_file, key_file, cert_der))
}

#[tokio::test]
async fn tcp_http_routing_by_prefix() -> TestResult<()> {
    let (a_addr, mut a_rx) = spawn_recording_server().await?;
    let (b_addr, mut b_rx) = spawn_recording_server().await?;

    let listen_addr = pick_free_port()?;
    let mut cfg = make_config(listen_addr, b_addr); // default backend B
    cfg.peek_http = true;
    cfg.http.routes = vec![
        HttpRoute { prefix: "/api".to_string(), backend: a_addr.to_string() },
        HttpRoute { prefix: "/".to_string(), backend: b_addr.to_string() },
    ];
    let cfg = Arc::new(cfg);

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        let counters = Arc::new(ConnectionCount::default());
        let (_tx, rx) = watch::channel(false);
        async move { tcp::run(cfg, counters, rx).await }
    });

    sleep(Duration::from_millis(50)).await;

    // /api goes to backend A
    {
        let mut client = TcpStream::connect(listen_addr).await?;
        client
            .write_all(b"GET /api/test HTTP/1.1\r\nHost: x\r\n\r\n")
            .await?;
        client.shutdown().await?;
        let buf = timeout(Duration::from_secs(1), a_rx.recv())
            .await?
            .ok_or("no data received on backend A")?;
        let text = std::str::from_utf8(&buf)?;
        assert!(text.starts_with("GET /api/test"));
    }
    // /other goes to backend B
    {
        let mut client = TcpStream::connect(listen_addr).await?;
        client
            .write_all(b"GET /other HTTP/1.1\r\nHost: x\r\n\r\n")
            .await?;
        client.shutdown().await?;
        let buf = timeout(Duration::from_secs(1), b_rx.recv())
            .await?
            .ok_or("no data received on backend B")?;
        let text = std::str::from_utf8(&buf)?;
        assert!(text.starts_with("GET /other"));
    }

    proxy.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_non_http_fallbacks_to_l4() -> TestResult<()> {
    let (b_addr, mut b_rx) = spawn_recording_server().await?;
    let listen_addr = pick_free_port()?;
    let mut cfg = make_config(listen_addr, b_addr);
    cfg.peek_http = true;
    cfg.http.routes = vec![];
    let cfg = Arc::new(cfg);

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        let counters = Arc::new(ConnectionCount::default());
        let (_tx, rx) = watch::channel(false);
        async move { tcp::run(cfg, counters, rx).await }
    });

    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(listen_addr).await?;
    client.write_all(b"\x01\x02\x03\x04payload").await?;
    client.shutdown().await?;
    let buf = timeout(Duration::from_secs(1), b_rx.recv())
        .await?
        .ok_or("no data received on backend")?;
    assert!(buf.starts_with(b"\x01\x02\x03\x04payload"));

    proxy.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_peek_disabled_uses_l4_backend() -> TestResult<()> {
    let (a_addr, mut a_rx) = spawn_recording_server().await?;
    let (b_addr, mut b_rx) = spawn_recording_server().await?;
    let listen_addr = pick_free_port()?;
    let mut cfg = make_config(listen_addr, a_addr); // L4 backend A
    cfg.peek_http = false;
    cfg.http.routes = vec![HttpRoute { prefix: "/api".into(), backend: b_addr.to_string() }];
    let cfg = Arc::new(cfg);

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        let counters = Arc::new(ConnectionCount::default());
        let (_tx, rx) = watch::channel(false);
        async move { tcp::run(cfg, counters, rx).await }
    });

    sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(listen_addr).await?;
    client
        .write_all(b"GET /api HTTP/1.1\r\nHost: x\r\n\r\n")
        .await?;
    client.shutdown().await?;
    let buf = timeout(Duration::from_secs(2), a_rx.recv())
        .await?
        .ok_or("no data received on backend A")?;
    let text = std::str::from_utf8(&buf)?;
    assert!(text.starts_with("GET /api"));

    // Backend B should not receive anything
    assert!(timeout(Duration::from_millis(200), b_rx.recv())
        .await
        .is_err());

    proxy.abort();
    Ok(())
}

#[tokio::test]
async fn tcp_tls_termination_http_routing() -> TestResult<()> {
    let (a_addr, mut a_rx) = spawn_recording_server().await?;
    let (b_addr, mut b_rx) = spawn_recording_server().await?;
    let listen_addr = pick_free_port()?;
    let (cert_file, key_file, cert_der) = make_self_signed_cert()?;

    let mut cfg = make_config(listen_addr, b_addr); // default backend B
    cfg.mode = Mode::TlsTermination;
    cfg.peek_http = true;
    cfg.http.routes = vec![
        HttpRoute { prefix: "/api".to_string(), backend: a_addr.to_string() },
        HttpRoute { prefix: "/".to_string(), backend: b_addr.to_string() },
    ];
    cfg.tls = Some(huginn_proxy_lib::config::types::TlsConfig {
        cert_path: cert_file.path().to_string_lossy().to_string(),
        key_path: key_file.path().to_string_lossy().to_string(),
        alpn: vec!["http/1.1".into()],
        server_names: vec!["localhost".into()],
        enable_fingerprint: true,
    });
    let cfg = Arc::new(cfg);

    let proxy = tokio::spawn({
        let cfg = cfg.clone();
        let counters = Arc::new(ConnectionCount::default());
        let (_tx, rx) = watch::channel(false);
        async move { tcp::run(cfg, counters, rx).await }
    });

    sleep(Duration::from_millis(50)).await;

    // Build TLS client with self-signed root
    let mut roots = RootCertStore::empty();
    let _ = roots.add_parsable_certificates([cert_der]);
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost")?;

    // /api goes to backend A
    {
        let tcp = TcpStream::connect(listen_addr).await?;
        let mut tls = connector.connect(server_name.clone(), tcp).await?;
        tls.write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        tls.shutdown().await?;
        let buf = timeout(Duration::from_secs(1), a_rx.recv())
            .await?
            .ok_or("no data received on backend A")?;
        let text = std::str::from_utf8(&buf)?;
        assert!(text.starts_with("GET /api/test"));
    }

    // /other goes to backend B
    {
        let tcp = TcpStream::connect(listen_addr).await?;
        let mut tls = connector.connect(server_name.clone(), tcp).await?;
        tls.write_all(b"GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        tls.shutdown().await?;
        let buf = timeout(Duration::from_secs(1), b_rx.recv())
            .await?
            .ok_or("no data received on backend B")?;
        let text = std::str::from_utf8(&buf)?;
        assert!(text.starts_with("GET /other"));
    }

    proxy.abort();
    Ok(())
}
