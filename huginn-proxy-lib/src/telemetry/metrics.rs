use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Registry;

#[allow(dead_code)]
#[derive(Clone)]
pub struct Metrics {
    pub connections_total: Counter<u64>,
    pub connections_active: UpDownCounter<i64>,

    pub requests_total: Counter<u64>,
    pub requests_duration_seconds: Histogram<f64>,

    pub fingerprints_extracted_total: Counter<u64>,
    pub fingerprint_extraction_duration_seconds: Histogram<f64>,

    pub backend_requests_total: Counter<u64>,
    pub backend_errors_total: Counter<u64>,
    pub backend_duration_seconds: Histogram<f64>,

    pub backend_selections_total: Counter<u64>,
    pub errors_total: Counter<u64>,
}

impl Metrics {
    #[allow(dead_code)] //TODO: Remove this once we have a proper implementation
    fn new(meter: Meter) -> Self {
        Self {
            connections_total: meter
                .u64_counter("huginn_connections_total")
                .with_description("Total number of connections established")
                .build(),
            connections_active: meter
                .i64_up_down_counter("huginn_connections_active")
                .with_description("Number of active connections")
                .build(),

            requests_total: meter
                .u64_counter("huginn_requests_total")
                .with_description("Total number of requests processed")
                .build(),
            requests_duration_seconds: meter
                .f64_histogram("huginn_requests_duration_seconds")
                .with_description("Request duration in seconds")
                .build(),

            fingerprints_extracted_total: meter
                .u64_counter("huginn_fingerprints_extracted_total")
                .with_description("Total number of fingerprints extracted")
                .build(),
            fingerprint_extraction_duration_seconds: meter
                .f64_histogram("huginn_fingerprint_extraction_duration_seconds")
                .with_description("Fingerprint extraction duration in seconds")
                .build(),

            backend_requests_total: meter
                .u64_counter("huginn_backend_requests_total")
                .with_description("Total number of requests to backends")
                .build(),
            backend_errors_total: meter
                .u64_counter("huginn_backend_errors_total")
                .with_description("Total number of backend errors")
                .build(),
            backend_duration_seconds: meter
                .f64_histogram("huginn_backend_duration_seconds")
                .with_description("Backend request duration in seconds")
                .build(),

            backend_selections_total: meter
                .u64_counter("huginn_backend_selections_total")
                .with_description("Total number of backend selections")
                .build(),

            errors_total: meter
                .u64_counter("huginn_errors_total")
                .with_description("Total number of errors")
                .build(),
        }
    }
}

#[allow(dead_code)]
pub fn init_metrics() -> Result<(Metrics, Registry), Box<dyn std::error::Error + Send + Sync>> {
    let registry = Registry::default();

    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()?;

    let meter_provider = SdkMeterProvider::builder()
        .with_reader(exporter)
        .build();

    global::set_meter_provider(meter_provider);

    let meter = global::meter("huginn-proxy");
    let metrics = Metrics::new(meter);

    Ok((metrics, registry))
}
