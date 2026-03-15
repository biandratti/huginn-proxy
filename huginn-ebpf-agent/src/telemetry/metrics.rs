use huginn_ebpf::{
    syn_captured_count_from_path, syn_insert_failures_count_from_path,
    syn_malformed_count_from_path,
};
use opentelemetry::global;
use opentelemetry::metrics::{Gauge, Meter};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Registry;
use std::sync::Arc;

pub mod labels {
    pub const VERSION: &str = "version";
    pub const RUST_VERSION: &str = "rust_version";
}

#[derive(Clone)]
pub struct Metrics {
    pub agent_up: Gauge<u64>,
    pub build_info: Gauge<u64>,
}

impl Metrics {
    fn new(meter: Meter) -> Self {
        Self {
            agent_up: meter
                .u64_gauge("agent_up")
                .with_description("1 if the agent has pinned maps and is running")
                .build(),
            build_info: meter
                .u64_gauge("huginn_ebpf_agent_build_info")
                .with_description("Build information (version, rust version)")
                .build(),
        }
    }

    pub fn set_ready(&self) {
        self.agent_up.record(1, &[]);
    }

    pub fn set_build_info(&self) {
        let version = env!("CARGO_PKG_VERSION");
        let rust_version = env!("CARGO_PKG_RUST_VERSION");
        self.build_info.record(
            1,
            &[
                KeyValue::new(labels::VERSION, version),
                KeyValue::new(labels::RUST_VERSION, rust_version),
            ],
        );
    }
}

pub fn init_metrics(
    pin_path: Arc<String>,
) -> Result<(Registry, Metrics), Box<dyn std::error::Error + Send + Sync>> {
    let registry = Registry::default();

    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()?;

    let meter_provider = SdkMeterProvider::builder().with_reader(exporter).build();
    global::set_meter_provider(meter_provider);

    let meter = global::meter("huginn-ebpf-agent");

    let pin_path_captured = pin_path.clone();
    let pin_path_failures = pin_path.clone();

    let _ = meter
        .u64_observable_counter("tcp_syn_captured_total")
        .with_description("Number of TCP SYN signatures successfully captured")
        .with_callback(move |observer| {
            let value = syn_captured_count_from_path(pin_path_captured.as_str()).unwrap_or(0);
            observer.observe(value, &[]);
        })
        .build();

    let _ = meter
        .u64_observable_counter("tcp_syn_insert_failures_total")
        .with_description("Number of TCP SYN map insert failures (e.g. LRU full)")
        .with_callback(move |observer| {
            let value =
                syn_insert_failures_count_from_path(pin_path_failures.as_str()).unwrap_or(0);
            observer.observe(value, &[]);
        })
        .build();

    let _ = meter
        .u64_observable_counter("tcp_syn_malformed_total")
        .with_description(
            "Number of malformed TCP packets (e.g. doff too short) that matched dst filter",
        )
        .with_callback(move |observer| {
            let value = syn_malformed_count_from_path(pin_path.as_str()).unwrap_or(0);
            observer.observe(value, &[]);
        })
        .build();

    let metrics = Metrics::new(meter);
    metrics.set_build_info();

    Ok((registry, metrics))
}
