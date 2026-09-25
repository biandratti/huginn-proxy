use std::convert::Infallible;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Full;
use huginn_proxy_lib::config::{
    Backend, Domain, FingerprintConfig, KeepAliveConfig, ListenConfig, LoggingConfig, ReloadConfig,
    Route, SecurityConfig, TelemetryConfig, TimeoutConfig, TlsConfig,
};
use huginn_proxy_lib::fingerprinting::names;
use huginn_proxy_lib::{Config, Metrics, WatchOptions};
use hyper::Response;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, Default)]
struct Captured {
    ja4: Option<String>,
    akamai: Option<String>,
}

fn free_port() -> Result<u16, BoxError> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

async fn spawn_echo_backend(
    captured: Arc<Mutex<Captured>>,
) -> Result<std::net::SocketAddr, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let captured = Arc::clone(&captured);
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let captured = Arc::clone(&captured);
                    async move {
                        let ja4 = req
                            .headers()
                            .get(names::TLS_JA4)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        let akamai = req
                            .headers()
                            .get(names::HTTP2_AKAMAI)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        *captured
                            .lock()
                            .unwrap_or_else(|e| panic!("mutex poisoned: {e}")) =
                            Captured { ja4, akamai };
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("ok"))))
                    }
                });
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Ok(addr)
}

fn dual_proxy_config(
    http_port: u16,
    https_port: u16,
    backend: std::net::SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Config {
    Config {
        listen: ListenConfig {
            port: Some(http_port),
            port_tls: Some(https_port),
            https_redirection: Some(false),
            address_v4: Some(vec!["127.0.0.1".to_string()]),
            ..Default::default()
        },
        backends: vec![Backend {
            address: backend.to_string(),
            http_version: None,
            health_check: None,
        }],
        domains: vec![Domain {
            host: Some("localhost".to_string()),
            cert_path: Some(cert.to_string_lossy().into_owned()),
            key_path: Some(key.to_string_lossy().into_owned()),
            client_ca_path: None,
            headers: None,
            security: None,
            fingerprinting: Some(true),
            routes: vec![Route {
                prefix: "/".to_string(),
                backend: backend.to_string(),
                fingerprinting: Some(true),
                force_new_connection: false,
                replace_path: None,
                security: None,
                headers: None,
            }],
        }],
        tls: Some(TlsConfig {
            alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
            options: Default::default(),
            session_resumption: Default::default(),
        }),
        fingerprint: FingerprintConfig {
            tls_enabled: true,
            http_enabled: true,
            tcp_enabled: false,
            max_capture: 64 * 1024,
        },
        logging: LoggingConfig { level: "warn".to_string(), show_target: false },
        timeout: TimeoutConfig {
            upstream_connect_ms: Some(5000),
            proxy_idle_ms: 30_000,
            drain_delay_secs: 0,
            shutdown_secs: 3,
            tls_handshake_secs: 10,
            connection_handling_secs: 60,
            keep_alive: KeepAliveConfig::default(),
        },
        security: SecurityConfig::default(),
        telemetry: TelemetryConfig {
            metrics_port: None,
            otel_log_level: "warn".to_string(),
            ..Default::default()
        },
        reload: ReloadConfig::default(),
        headers: None,
        preserve_host: false,
        backend_pool: Default::default(),
    }
}

async fn wait_for_listen(addr: std::net::SocketAddr) -> Result<(), BoxError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("proxy at {addr} did not become ready"))?;
    Ok(())
}

fn snapshot(captured: &Arc<Mutex<Captured>>) -> Captured {
    captured
        .lock()
        .unwrap_or_else(|e| panic!("mutex poisoned: {e}"))
        .clone()
}

#[tokio::test]
async fn dual_listen_ja4_only_on_https_akamai_on_http2() -> Result<(), BoxError> {
    let captured: Arc<Mutex<Captured>> = Arc::new(Mutex::new(Captured::default()));
    let backend_addr = spawn_echo_backend(Arc::clone(&captured)).await?;
    let http_port = free_port()?;
    let https_port = free_port()?;
    let http_addr: std::net::SocketAddr = format!("127.0.0.1:{http_port}").parse()?;
    let https_addr: std::net::SocketAddr = format!("127.0.0.1:{https_port}").parse()?;

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_file = tempfile::NamedTempFile::new()?;
    let key_file = tempfile::NamedTempFile::new()?;
    fs::write(cert_file.path(), cert.pem())?;
    fs::write(key_file.path(), signing_key.serialize_pem())?;

    let config =
        dual_proxy_config(http_port, https_port, backend_addr, cert_file.path(), key_file.path());
    let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
    let proxy_task = tokio::spawn(async move {
        let (shutdown_tx, _) = huginn_proxy_lib::shutdown_channel();
        let _ = huginn_proxy_lib::run(
            Arc::new(static_cfg),
            Arc::new(ArcSwap::from_pointee(dynamic_cfg)),
            Metrics::new_noop(),
            None,
            WatchOptions::default(),
            shutdown_tx,
            huginn_proxy_lib::Readiness::new(),
        )
        .await;
    });

    wait_for_listen(http_addr).await?;
    wait_for_listen(https_addr).await?;

    let https_h2 = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = https_h2
        .get(format!("https://localhost:{https_port}/"))
        .send()
        .await?;
    assert!(resp.status().is_success(), "HTTPS HTTP/2: {}", resp.status());
    let https_h2_fp = snapshot(&captured);
    assert!(
        https_h2_fp.ja4.as_ref().is_some_and(|s| !s.is_empty()),
        "HTTPS HTTP/2 must inject JA4, got {https_h2_fp:?}"
    );
    assert!(
        https_h2_fp.akamai.as_ref().is_some_and(|s| !s.is_empty()),
        "HTTPS HTTP/2 must inject Akamai, got {https_h2_fp:?}"
    );

    let h2c = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = h2c
        .get(format!("http://localhost:{http_port}/"))
        .send()
        .await?;
    assert!(resp.status().is_success(), "h2c: {}", resp.status());
    let h2c_fp = snapshot(&captured);
    assert!(h2c_fp.ja4.is_none(), "plaintext HTTP/2 must not inject JA4, got {h2c_fp:?}");
    assert!(
        h2c_fp.akamai.as_ref().is_some_and(|s| !s.is_empty()),
        "plaintext HTTP/2 must inject Akamai, got {h2c_fp:?}"
    );

    let https_h1 = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = https_h1
        .get(format!("https://localhost:{https_port}/"))
        .send()
        .await?;
    assert!(resp.status().is_success(), "HTTPS HTTP/1.1: {}", resp.status());
    let https_h1_fp = snapshot(&captured);
    assert!(
        https_h1_fp.ja4.as_ref().is_some_and(|s| !s.is_empty()),
        "HTTPS HTTP/1.1 must inject JA4, got {https_h1_fp:?}"
    );
    assert!(
        https_h1_fp.akamai.is_none(),
        "HTTPS HTTP/1.1 must not inject Akamai, got {https_h1_fp:?}"
    );

    let http11 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = http11
        .get(format!("http://localhost:{http_port}/"))
        .send()
        .await?;
    assert!(resp.status().is_success(), "HTTP/1.1: {}", resp.status());
    let http11_fp = snapshot(&captured);
    assert!(
        http11_fp.ja4.is_none(),
        "plaintext HTTP/1.1 must not inject JA4, got {http11_fp:?}"
    );
    assert!(
        http11_fp.akamai.is_none(),
        "plaintext HTTP/1.1 must not inject Akamai, got {http11_fp:?}"
    );

    proxy_task.abort();
    Ok(())
}
