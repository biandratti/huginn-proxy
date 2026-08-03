use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::WatchOptions;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), BoxError>;

/// Requests sent to an unrouted path; each must add exactly one to the counter.
const REJECTED_REQUESTS: usize = 3;

fn free_port() -> Result<u16, BoxError> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Value of `huginn_errors_total` for `error_type`, or `0` when the series has no sample yet.
///
/// Matches on the name prefix because the OpenTelemetry Prometheus exporter appends its own
/// `_total` suffix to counters.
fn error_count(registry: &prometheus::Registry, error_type: &str) -> f64 {
    registry
        .gather()
        .iter()
        .filter(|family| family.name().starts_with("huginn_errors"))
        .flat_map(|family| family.get_metric())
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|l| l.name() == "error_type" && l.value() == error_type)
        })
        .map_or(0.0, |metric| metric.get_counter().value())
}

/// Send one plain HTTP/1.1 request and return the response text.
async fn request(proxy: SocketAddr, path: &str) -> Result<String, BoxError> {
    let mut stream = TcpStream::connect(proxy).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[tokio::test]
async fn a_rejected_request_is_counted_once() -> TestResult {
    let (metrics, registry) = huginn_proxy_lib::telemetry::init_metrics()?;

    // The backend is never dialed: the request is rejected before backend selection.
    let port = free_port()?;
    let toml = format!(
        r#"listen = {{ addrs = ["127.0.0.1:{port}"] }}
backends = [{{ address = "127.0.0.1:1" }}]

[[domains]]
host = "127.0.0.1"
routes = [{{ prefix = "/api", backend = "127.0.0.1:1" }}]
"#
    );
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;
    std::fs::write(tmp.path(), &toml)?;

    let config = load_from_path(tmp.path())?;
    let listen_addr = config.listen.addrs[0];
    let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();

    let _proxy = tokio::spawn(async move {
        let (shutdown_tx, _) = huginn_proxy_lib::shutdown_channel();
        let _ = huginn_proxy_lib::run(
            Arc::new(static_cfg),
            Arc::new(ArcSwap::from_pointee(dynamic_cfg)),
            metrics,
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

    assert_eq!(
        error_count(&registry, "no_matching_route"),
        0.0,
        "no request has been rejected yet"
    );

    for _ in 0..REJECTED_REQUESTS {
        let response = request(listen_addr, "/nope").await?;
        assert!(response.contains("404"), "expected a 404, got: {response}");
    }

    assert_eq!(
        error_count(&registry, "no_matching_route"),
        REJECTED_REQUESTS as f64,
        "each rejected request must add exactly one to huginn_errors_total"
    );

    // `tmp` is read at startup and must outlive the proxy task.
    std::mem::forget(tmp);
    Ok(())
}
