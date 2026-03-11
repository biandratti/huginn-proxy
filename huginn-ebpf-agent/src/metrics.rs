use opentelemetry::global;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, Registry, TextEncoder};
use std::sync::Arc;

use huginn_ebpf::syn_insert_failures_count_from_path;

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
    pub fn set_ready(&self) {
        self.agent_up.record(1, &[]);
    }
}

pub fn encode_metrics(
    registry: &Registry,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}
