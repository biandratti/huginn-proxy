//! Clients that never finish the ClientHello must be closed after `tls_handshake_secs`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use huginn_proxy_lib::config::{
    Backend, Domain, FingerprintConfig, KeepAliveConfig, ListenConfig, LoggingConfig, Route,
    SecurityConfig, TelemetryConfig, TimeoutConfig,
};
use huginn_proxy_lib::{Config, Metrics, TlsConfig, WatchOptions};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const HANDSHAKE_TIMEOUT_SECS: u64 = 1;

fn free_port() -> Result<u16, BoxError> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// TLS proxy with a short handshake timeout. Backend is unused, so it points nowhere.
async fn spawn_tls_proxy() -> Result<(std::net::SocketAddr, tokio::task::AbortHandle), BoxError> {
    static CRYPTO_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    CRYPTO_INIT.get_or_init(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_file = tempfile::Builder::new().suffix(".crt").tempfile()?;
    let key_file = tempfile::Builder::new().suffix(".key").tempfile()?;
    std::fs::write(cert_file.path(), cert.pem())?;
    std::fs::write(key_file.path(), signing_key.serialize_pem())?;

    let listen_port = free_port()?;
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse()?;
    let backend = "127.0.0.1:1".to_string();

    let config = Config {
        listen: ListenConfig::localhost_https(listen_port),
        backends: vec![Backend {
            address: backend.clone(),
            http_version: None,
            health_check: None,
        }],
        domains: vec![Domain {
            host: Some("localhost".to_string()),
            cert_path: Some(cert_file.path().to_string_lossy().into_owned()),
            key_path: Some(key_file.path().to_string_lossy().into_owned()),
            client_ca_path: None,
            headers: None,
            security: None,
            fingerprinting: None,
            routes: vec![Route {
                prefix: "/".to_string(),
                backend,
                fingerprinting: None,
                force_new_connection: false,
                replace_path: None,
                security: None,
                headers: None,
            }],
        }],
        tls: Some(TlsConfig {
            alpn: Some(vec!["http/1.1".to_string()]),
            options: Default::default(),
            session_resumption: Default::default(),
        }),
        fingerprint: FingerprintConfig {
            tls_enabled: true,
            http_enabled: false,
            tcp_enabled: false,
            max_capture: 0,
        },
        logging: LoggingConfig { level: "error".to_string(), show_target: false },
        timeout: TimeoutConfig {
            upstream_connect_ms: Some(1000),
            proxy_idle_ms: 30_000,
            drain_delay_secs: 0,
            shutdown_secs: 1,
            tls_handshake_secs: HANDSHAKE_TIMEOUT_SECS,
            connection_handling_secs: 60,
            keep_alive: KeepAliveConfig::default(),
        },
        security: SecurityConfig::default(),
        telemetry: TelemetryConfig {
            metrics_port: None,
            otel_log_level: "error".to_string(),
            ..Default::default()
        },
        reload: huginn_proxy_lib::config::ReloadConfig::default(),
        headers: None,
        preserve_host: false,
        backend_pool: Default::default(),
    };

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
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("TLS proxy at {listen_addr} did not become ready"))?;

    // Keep cert files on disk while the proxy runs.
    std::mem::forget(cert_file);
    std::mem::forget(key_file);

    Ok((listen_addr, handle.abort_handle()))
}

/// Pass if the proxy closes or resets `stream` once the handshake timeout has run out,
/// counted from `connected_at`. Closing too early means something other than the timeout did it.
async fn assert_closed_by_proxy(
    mut stream: impl AsyncRead + Unpin,
    connected_at: Instant,
) -> Result<(), BoxError> {
    let min =
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS).saturating_sub(Duration::from_millis(100));
    let limit = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS * 5);
    let mut buf = [0u8; 64];
    match tokio::time::timeout(limit, stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {
            let elapsed = connected_at.elapsed();
            if elapsed < min {
                return Err(format!(
                    "proxy closed after {elapsed:?}, before the {HANDSHAKE_TIMEOUT_SECS}s handshake timeout"
                )
                .into());
            }
            Ok(())
        }
        Ok(Ok(n)) => Err(format!("expected the proxy to close, but it sent {n} bytes").into()),
        Err(_) => {
            Err(format!("proxy kept an idle pre-handshake connection open for {limit:?}").into())
        }
    }
}

#[tokio::test]
async fn silent_client_is_disconnected_after_handshake_timeout() -> Result<(), BoxError> {
    let (proxy, _handle) = spawn_tls_proxy().await?;
    let stream = TcpStream::connect(proxy).await?;
    let connected_at = Instant::now();
    assert_closed_by_proxy(stream, connected_at).await
}

#[tokio::test]
async fn partial_client_hello_is_disconnected_after_handshake_timeout() -> Result<(), BoxError> {
    let (proxy, _handle) = spawn_tls_proxy().await?;
    let mut stream = TcpStream::connect(proxy).await?;
    let connected_at = Instant::now();
    // Start of a TLS record header, then silence.
    stream.write_all(&[0x16, 0x03, 0x01]).await?;
    assert_closed_by_proxy(stream, connected_at).await
}

const CLIENT_HELLO: &[u8] = include_bytes!("../../../benches/fixtures/clienthello_reqwest.bin");

/// `CLIENT_HELLO` split into records of at most 64 payload bytes.
fn client_hello_records() -> Vec<Vec<u8>> {
    CLIENT_HELLO[5..]
        .chunks(64)
        .map(|part| {
            let mut record = CLIENT_HELLO[..3].to_vec();
            record.extend_from_slice(&u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes());
            record.extend_from_slice(part);
            record
        })
        .collect()
}

#[tokio::test]
async fn fragmented_client_hello_is_disconnected_after_handshake_timeout() -> Result<(), BoxError> {
    let (proxy, _handle) = spawn_tls_proxy().await?;
    let records = client_hello_records();
    assert!(records.len() > 1);

    let mut stalled = TcpStream::connect(proxy).await?;
    let stalled_at = Instant::now();
    stalled.write_all(&records[0]).await?;

    let (drip_read, mut drip_write) = TcpStream::connect(proxy).await?.into_split();
    let drip_at = Instant::now();
    let interval = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS * 2) / records.len() as u32;
    let _writer = tokio::spawn(async move {
        for record in records {
            if drip_write.write_all(&record).await.is_err() {
                return;
            }
            tokio::time::sleep(interval).await;
        }
        tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS * 10)).await;
    });

    tokio::try_join!(
        assert_closed_by_proxy(stalled, stalled_at),
        assert_closed_by_proxy(drip_read, drip_at),
    )?;
    Ok(())
}
