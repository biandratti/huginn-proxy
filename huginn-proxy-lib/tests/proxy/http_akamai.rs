use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Full;
use huginn_proxy_lib::config::{
    Backend, Domain, FingerprintConfig, KeepAliveConfig, ListenConfig, LoggingConfig, ReloadConfig,
    Route, SecurityConfig, TelemetryConfig, TimeoutConfig,
};
use huginn_proxy_lib::fingerprinting::names;
use huginn_proxy_lib::{Config, Metrics, WatchOptions};
use hyper::Response;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn free_port() -> Result<u16, BoxError> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

async fn spawn_echo_backend(
    captured: Arc<Mutex<Option<String>>>,
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
                        if let Some(v) = req.headers().get(names::HTTP2_AKAMAI) {
                            *captured
                                .lock()
                                .unwrap_or_else(|e| panic!("mutex poisoned: {e}")) =
                                Some(v.to_str().unwrap_or("").to_string());
                        }
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

fn http_proxy_config(proxy_port: u16, backend: std::net::SocketAddr) -> Config {
    Config {
        listen: ListenConfig::localhost_http(proxy_port),
        backends: vec![Backend {
            address: backend.to_string(),
            http_version: None,
            health_check: None,
        }],
        domains: vec![Domain {
            host: Some("127.0.0.1".to_string()),
            cert_path: None,
            key_path: None,
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
        tls: None,
        fingerprint: FingerprintConfig {
            tls_enabled: false,
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

#[tokio::test]
async fn h2c_prior_knowledge_injects_akamai() -> Result<(), BoxError> {
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let backend_addr = spawn_echo_backend(Arc::clone(&captured)).await?;
    let proxy_port = free_port()?;
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{proxy_port}").parse()?;

    let config = http_proxy_config(proxy_port, backend_addr);
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

    wait_for_listen(proxy_addr).await?;

    let resp = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(5))
        .build()?
        .get(format!("http://{proxy_addr}/"))
        .send()
        .await?;
    assert!(resp.status().is_success());

    proxy_task.abort();

    let akamai = captured
        .lock()
        .unwrap_or_else(|e| panic!("mutex poisoned: {e}"))
        .clone();
    assert!(
        akamai.as_ref().is_some_and(|s| !s.is_empty()),
        "plaintext HTTP/2 prior knowledge must inject x-http2-akamai, got {akamai:?}"
    );
    Ok(())
}

#[tokio::test]
async fn http11_does_not_inject_akamai() -> Result<(), BoxError> {
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let backend_addr = spawn_echo_backend(Arc::clone(&captured)).await?;
    let proxy_port = free_port()?;
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{proxy_port}").parse()?;

    let config = http_proxy_config(proxy_port, backend_addr);
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

    wait_for_listen(proxy_addr).await?;

    let resp = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()?
        .get(format!("http://{proxy_addr}/"))
        .send()
        .await?;
    assert!(resp.status().is_success());

    proxy_task.abort();

    let akamai = captured
        .lock()
        .unwrap_or_else(|e| panic!("mutex poisoned: {e}"))
        .clone();
    assert!(akamai.is_none(), "HTTP/1.1 must not inject x-http2-akamai, got {akamai:?}");
    Ok(())
}
