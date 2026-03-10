//! OpenTelemetry metrics + Prometheus exporter, same pattern as huginn-proxy-lib.
//! Serves GET /metrics (Prometheus scrape) and GET /ready (readiness) on localhost.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use opentelemetry::global;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, Registry, TextEncoder};
use tracing::info;

use huginn_ebpf::pin;
use huginn_ebpf::syn_insert_failures_count_from_path;

const METRICS_PORT: u16 = 9091;
const BIND_ADDR: &str = "127.0.0.1";

/// Agent metrics: observable counter from BPF map + gauge for agent_up.
pub(crate) struct AgentMetrics {
    agent_up: opentelemetry::metrics::Gauge<u64>,
}

pub fn init_metrics(
    pin_path: Arc<String>,
) -> Result<(Registry, AgentMetrics), Box<dyn std::error::Error + Send + Sync>> {
    let registry = Registry::default();

    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()?;

    let meter_provider = SdkMeterProvider::builder().with_reader(exporter).build();
    global::set_meter_provider(meter_provider);

    let meter = global::meter("huginn-ebpf-agent");

    // Observable counter: value read from BPF map on each scrape
    let _ = meter
        .u64_observable_counter("tcp_syn_insert_failures_total")
        .with_description("Number of TCP SYN map insert failures (e.g. LRU full)")
        .with_callback(move |observer| {
            let value = syn_insert_failures_count_from_path(pin_path.as_str()).unwrap_or(0);
            observer.observe(value, &[]);
        })
        .build();

    let agent_up = meter
        .u64_gauge("agent_up")
        .with_description("1 if the agent has pinned maps and is running")
        .build();

    let metrics = AgentMetrics { agent_up };

    Ok((registry, metrics))
}

impl AgentMetrics {
    /// Call after pin_maps() so readiness and agent_up reflect running state.
    pub fn set_ready(&self) {
        self.agent_up.record(1, &[]);
    }
}

pub fn spawn_server(registry: Arc<Registry>, pin_path: String) {
    thread::spawn(move || {
        let listener = match TcpListener::bind((BIND_ADDR, METRICS_PORT)) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%e, "metrics server: bind failed");
                return;
            }
        };
        let addr = listener.local_addr().unwrap_or_else(|e| {
            tracing::error!(%e, "metrics server: local_addr failed");
            std::process::exit(1);
        });
        info!(%addr, "metrics server listening");
        for stream in listener.incoming().flatten() {
            let registry = Arc::clone(&registry);
            let pin_path = pin_path.clone();
            thread::spawn(move || handle(stream, &registry, &pin_path));
        }
    });
}

fn handle(mut stream: std::net::TcpStream, registry: &Registry, pin_path: &str) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
    let mut reader = BufReader::new(&stream);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).is_err() {
        return;
    }
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    let (status, body): (_, String) = match path {
        "/metrics" => match encode_metrics(registry) {
            Ok(s) => ("200 OK", s),
            Err(e) => {
                tracing::warn!(%e, "metrics encode failed");
                ("500 Internal Server Error", format!("Error: {e}\n"))
            }
        },
        "/ready" => ready_response(pin_path),
        _ => ("404 Not Found", "Not Found\r\n".to_string()),
    };
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{}",
        status, body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn encode_metrics(registry: &Registry) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

/// /ready: 200 if BPF pins exist at pin_path, else 503.
fn ready_response(pin_path: &str) -> (&'static str, String) {
    if pins_exist(pin_path) {
        ("200 OK", "ok\n".to_string())
    } else {
        ("503 Service Unavailable", "pins not ready\n".to_string())
    }
}

/// Standalone readiness check from pin path (for tests or alternate /ready impl).
pub fn pins_exist(base: &str) -> bool {
    let base = Path::new(base);
    base.join(pin::SYN_MAP_V4_NAME).exists()
        && base.join(pin::COUNTER_NAME).exists()
        && base.join(pin::SYN_INSERT_FAILURES_NAME).exists()
}
