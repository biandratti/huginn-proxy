use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Registry;
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    pub connections_total: Counter<u64>,
    pub connections_active: UpDownCounter<i64>,

    pub requests_total: Counter<u64>,
    pub requests_duration_seconds: Histogram<f64>,

    // TLS fingerprinting metrics (JA4)
    pub tls_fingerprints_extracted_total: Counter<u64>,
    pub tls_fingerprint_extraction_duration_seconds: Histogram<f64>,
    pub tls_fingerprint_failures_total: Counter<u64>,

    // HTTP/2 fingerprinting metrics (Akamai)
    pub http2_fingerprints_extracted_total: Counter<u64>,
    pub http2_fingerprint_extraction_duration_seconds: Histogram<f64>,
    pub http2_fingerprint_failures_total: Counter<u64>,

    pub backend_requests_total: Counter<u64>,
    pub backend_errors_total: Counter<u64>,
    pub backend_duration_seconds: Histogram<f64>,

    pub backend_selections_total: Counter<u64>,
    pub errors_total: Counter<u64>,

    // TLS handshake metrics
    pub tls_handshakes_total: Counter<u64>,
    pub tls_handshake_duration_seconds: Histogram<f64>,
    pub tls_handshake_errors_total: Counter<u64>,
    pub tls_connections_active: UpDownCounter<i64>,

    // Connection limit metrics
    pub connections_rejected_total: Counter<u64>,
}

impl Metrics {
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

            tls_fingerprints_extracted_total: meter
                .u64_counter("huginn_tls_fingerprints_extracted_total")
                .with_description("Total number of TLS (JA4) fingerprints extracted")
                .build(),
            tls_fingerprint_extraction_duration_seconds: meter
                .f64_histogram("huginn_tls_fingerprint_extraction_duration_seconds")
                .with_description("TLS fingerprint extraction duration in seconds")
                .build(),
            tls_fingerprint_failures_total: meter
                .u64_counter("huginn_tls_fingerprint_failures_total")
                .with_description("Total number of TLS fingerprint extraction failures")
                .build(),

            http2_fingerprints_extracted_total: meter
                .u64_counter("huginn_http2_fingerprints_extracted_total")
                .with_description("Total number of HTTP/2 (Akamai) fingerprints extracted")
                .build(),
            http2_fingerprint_extraction_duration_seconds: meter
                .f64_histogram("huginn_http2_fingerprint_extraction_duration_seconds")
                .with_description("HTTP/2 fingerprint extraction duration in seconds")
                .build(),
            http2_fingerprint_failures_total: meter
                .u64_counter("huginn_http2_fingerprint_failures_total")
                .with_description("Total number of HTTP/2 fingerprint extraction failures (includes HTTP/1.1 connections)")
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

            tls_handshakes_total: meter
                .u64_counter("huginn_tls_handshakes_total")
                .with_description("Total number of TLS handshakes completed")
                .build(),
            tls_handshake_duration_seconds: meter
                .f64_histogram("huginn_tls_handshake_duration_seconds")
                .with_description("TLS handshake duration in seconds")
                .build(),
            tls_handshake_errors_total: meter
                .u64_counter("huginn_tls_handshake_errors_total")
                .with_description("Total number of TLS handshake errors")
                .build(),
            tls_connections_active: meter
                .i64_up_down_counter("huginn_tls_connections_active")
                .with_description("Number of active TLS connections")
                .build(),

            connections_rejected_total: meter
                .u64_counter("huginn_connections_rejected_total")
                .with_description("Total number of connections rejected due to connection limit")
                .build(),
        }
    }
}

pub fn init_metrics() -> Result<(Arc<Metrics>, Registry), Box<dyn std::error::Error + Send + Sync>>
{
    let registry = Registry::default();

    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()?;

    let meter_provider = SdkMeterProvider::builder().with_reader(exporter).build();

    global::set_meter_provider(meter_provider);

    let meter = global::meter("huginn-proxy");
    let metrics = Arc::new(Metrics::new(meter));

    Ok((metrics, registry))
}
