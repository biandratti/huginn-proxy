use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter, UpDownCounter};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Registry;
use std::sync::Arc;

pub mod labels {
    pub const ERROR_TYPE: &str = "error_type";
    pub const STRATEGY: &str = "strategy";
    pub const ROUTE: &str = "route";
    pub const PROTOCOL: &str = "protocol";
    pub const STATUS_CODE: &str = "status_code";
    pub const METHOD: &str = "method";
    pub const CONTEXT: &str = "context";
    pub const BACKEND_ADDRESS: &str = "backend_address";
    pub const TLS_VERSION: &str = "tls_version";
    pub const CIPHER_SUITE: &str = "cipher_suite";
    pub const TIMEOUT_TYPE: &str = "timeout_type";
    pub const REASON: &str = "reason";
    pub const COMPONENT: &str = "component";
    pub const VERSION: &str = "version";
    pub const RUST_VERSION: &str = "rust_version";
    pub const BACKEND: &str = "backend";
}

pub mod values {
    pub const ERROR_RATE_LIMITED: &str = "rate_limited";
    pub const ERROR_IP_BLOCKED: &str = "ip_blocked";
    pub const TIMEOUT_TLS_HANDSHAKE: &str = "tls_handshake";
    pub const TIMEOUT_CONNECTION_HANDLING: &str = "connection_handling";
    pub const CONTEXT_REQUEST: &str = "request";
    pub const CONTEXT_RESPONSE: &str = "response";
}

#[derive(Clone)]
pub struct Metrics {
    pub connections_total: Counter<u64>,
    pub connections_active: UpDownCounter<i64>,

    pub requests_total: Counter<u64>,
    pub requests_duration_seconds: Histogram<f64>,

    // Throughput metrics
    pub bytes_received_total: Counter<u64>,
    pub bytes_sent_total: Counter<u64>,

    // TLS fingerprinting metrics (JA4)
    pub tls_fingerprints_extracted_total: Counter<u64>,
    pub tls_fingerprint_extraction_duration_seconds: Histogram<f64>,
    pub tls_fingerprint_failures_total: Counter<u64>,

    // HTTP/2 fingerprinting metrics (Akamai)
    pub http2_fingerprints_extracted_total: Counter<u64>,
    pub http2_fingerprint_extraction_duration_seconds: Histogram<f64>,
    pub http2_fingerprint_failures_total: Counter<u64>,

    // TCP SYN fingerprinting metrics (p0f-style via eBPF)
    // result label: "hit" | "miss" | "malformed"
    pub tcp_syn_fingerprints_total: Counter<u64>,
    pub tcp_syn_fingerprint_duration_seconds: Histogram<f64>,
    pub tcp_syn_fingerprint_failures_total: Counter<u64>,

    pub backend_requests_total: Counter<u64>,
    pub backend_errors_total: Counter<u64>,
    pub backend_duration_seconds: Histogram<f64>,

    // Backend throughput metrics
    pub backend_bytes_received_total: Counter<u64>,
    pub backend_bytes_sent_total: Counter<u64>,

    pub backend_selections_total: Counter<u64>,
    pub errors_total: Counter<u64>,

    // TLS handshake metrics
    pub tls_handshakes_total: Counter<u64>,
    pub tls_handshake_duration_seconds: Histogram<f64>,
    pub tls_handshake_errors_total: Counter<u64>,
    pub tls_connections_active: UpDownCounter<i64>,

    // Connection limit metrics
    pub connections_rejected_total: Counter<u64>,

    // Timeout metrics
    pub timeouts_total: Counter<u64>,

    // Rate limiting metrics
    pub rate_limit_requests_total: Counter<u64>,
    pub rate_limit_allowed_total: Counter<u64>,
    pub rate_limit_rejected_total: Counter<u64>,

    // IP filtering metrics
    pub ip_filter_requests_total: Counter<u64>,
    pub ip_filter_allowed_total: Counter<u64>,
    pub ip_filter_denied_total: Counter<u64>,

    // Header manipulation metrics
    pub headers_added_total: Counter<u64>,
    pub headers_removed_total: Counter<u64>,

    // mTLS metrics
    pub mtls_connections_total: Counter<u64>,

    // Build info
    pub build_info: Gauge<u64>,
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

            bytes_received_total: meter
                .u64_counter("huginn_bytes_received_total")
                .with_description("Total bytes received from clients")
                .build(),
            bytes_sent_total: meter
                .u64_counter("huginn_bytes_sent_total")
                .with_description("Total bytes sent to clients")
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

            tcp_syn_fingerprints_total: meter
                .u64_counter("huginn_tcp_syn_fingerprints_total")
                .with_description("Total TCP SYN fingerprint lookups. result=hit|miss|malformed")
                .build(),
            tcp_syn_fingerprint_duration_seconds: meter
                .f64_histogram("huginn_tcp_syn_fingerprint_duration_seconds")
                .with_description("TCP SYN fingerprint BPF map lookup and parse duration in seconds")
                .build(),
            tcp_syn_fingerprint_failures_total: meter
                .u64_counter("huginn_tcp_syn_fingerprint_failures_total")
                .with_description("Total number of TCP SYN fingerprint extraction failures (malformed BPF map entries)")
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

            backend_bytes_received_total: meter
                .u64_counter("huginn_backend_bytes_received_total")
                .with_description("Total bytes received from backends")
                .build(),
            backend_bytes_sent_total: meter
                .u64_counter("huginn_backend_bytes_sent_total")
                .with_description("Total bytes sent to backends")
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

            timeouts_total: meter
                .u64_counter("huginn_timeouts_total")
                .with_description("Total number of timeouts by type (tls_handshake, http_read, http_write, connection_handling)")
                .build(),

            rate_limit_requests_total: meter
                .u64_counter("huginn_rate_limit_requests_total")
                .with_description("Total number of requests evaluated by rate limiter")
                .build(),
            rate_limit_allowed_total: meter
                .u64_counter("huginn_rate_limit_allowed_total")
                .with_description("Total number of requests allowed by rate limiter")
                .build(),
            rate_limit_rejected_total: meter
                .u64_counter("huginn_rate_limit_rejected_total")
                .with_description("Total number of requests rejected by rate limiter (429)")
                .build(),

            ip_filter_requests_total: meter
                .u64_counter("huginn_ip_filter_requests_total")
                .with_description("Total number of requests evaluated by IP filter")
                .build(),
            ip_filter_allowed_total: meter
                .u64_counter("huginn_ip_filter_allowed_total")
                .with_description("Total number of requests allowed by IP filter")
                .build(),
            ip_filter_denied_total: meter
                .u64_counter("huginn_ip_filter_denied_total")
                .with_description("Total number of requests denied by IP filter (403)")
                .build(),

            headers_added_total: meter
                .u64_counter("huginn_headers_added_total")
                .with_description("Total number of headers added by header manipulation")
                .build(),
            headers_removed_total: meter
                .u64_counter("huginn_headers_removed_total")
                .with_description("Total number of headers removed by header manipulation")
                .build(),

            mtls_connections_total: meter
                .u64_counter("huginn_mtls_connections_total")
                .with_description("Total number of connections with mTLS enabled (client certificate authentication)")
                .build(),

            build_info: meter
                .u64_gauge("huginn_build_info")
                .with_description("Build information (version, rust version)")
                .build(),
        }
    }

    /// Set build info metric with version labels
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

    pub fn record_rate_limit_rejection(&self, strategy: &str, route: &str) {
        self.errors_total
            .add(1, &[KeyValue::new(labels::ERROR_TYPE, values::ERROR_RATE_LIMITED)]);
        self.rate_limit_rejected_total.add(
            1,
            &[
                KeyValue::new(labels::STRATEGY, strategy.to_string()),
                KeyValue::new(labels::ROUTE, route.to_string()),
            ],
        );
    }

    pub fn record_rate_limit_allowed(&self, strategy: &str, route: &str) {
        self.rate_limit_allowed_total.add(
            1,
            &[
                KeyValue::new(labels::STRATEGY, strategy.to_string()),
                KeyValue::new(labels::ROUTE, route.to_string()),
            ],
        );
    }

    pub fn record_rate_limit_request(&self, strategy: &str, route: &str) {
        self.rate_limit_requests_total.add(
            1,
            &[
                KeyValue::new(labels::STRATEGY, strategy.to_string()),
                KeyValue::new(labels::ROUTE, route.to_string()),
            ],
        );
    }

    pub fn record_headers_added(&self, count: u64, context: &str) {
        if count > 0 {
            self.headers_added_total
                .add(count, &[KeyValue::new(labels::CONTEXT, context.to_string())]);
        }
    }

    pub fn record_headers_removed(&self, count: u64, context: &str) {
        if count > 0 {
            self.headers_removed_total
                .add(count, &[KeyValue::new(labels::CONTEXT, context.to_string())]);
        }
    }

    pub fn record_ip_filter_allowed(&self) {
        self.ip_filter_requests_total.add(1, &[]);
        self.ip_filter_allowed_total.add(1, &[]);
    }

    pub fn record_ip_filter_denied(&self) {
        self.ip_filter_requests_total.add(1, &[]);
        self.ip_filter_denied_total.add(1, &[]);
    }

    pub fn record_bytes_received(&self, bytes: u64, protocol: &str) {
        if bytes > 0 {
            self.bytes_received_total
                .add(bytes, &[KeyValue::new(labels::PROTOCOL, protocol.to_string())]);
        }
    }

    pub fn record_bytes_sent(&self, bytes: u64, protocol: &str) {
        if bytes > 0 {
            self.bytes_sent_total
                .add(bytes, &[KeyValue::new(labels::PROTOCOL, protocol.to_string())]);
        }
    }

    pub fn record_backend_bytes_received(&self, bytes: u64, backend: &str, route: &str) {
        if bytes > 0 {
            self.backend_bytes_received_total.add(
                bytes,
                &[
                    KeyValue::new(labels::BACKEND_ADDRESS, backend.to_string()),
                    KeyValue::new(labels::ROUTE, route.to_string()),
                ],
            );
        }
    }

    pub fn record_backend_bytes_sent(&self, bytes: u64, backend: &str, route: &str) {
        if bytes > 0 {
            self.backend_bytes_sent_total.add(
                bytes,
                &[
                    KeyValue::new(labels::BACKEND_ADDRESS, backend.to_string()),
                    KeyValue::new(labels::ROUTE, route.to_string()),
                ],
            );
        }
    }

    pub fn record_backend_request(
        &self,
        backend: &str,
        status_code: u16,
        protocol: &str,
        route: &str,
    ) {
        self.backend_requests_total.add(
            1,
            &[
                KeyValue::new(labels::BACKEND_ADDRESS, backend.to_string()),
                KeyValue::new(labels::STATUS_CODE, status_code.to_string()),
                KeyValue::new(labels::PROTOCOL, protocol.to_string()),
                KeyValue::new(labels::ROUTE, route.to_string()),
            ],
        );
    }

    pub fn record_backend_duration(
        &self,
        duration: f64,
        backend: &str,
        status_code: u16,
        protocol: &str,
        route: &str,
    ) {
        self.backend_duration_seconds.record(
            duration,
            &[
                KeyValue::new(labels::BACKEND_ADDRESS, backend.to_string()),
                KeyValue::new(labels::STATUS_CODE, status_code.to_string()),
                KeyValue::new(labels::PROTOCOL, protocol.to_string()),
                KeyValue::new(labels::ROUTE, route.to_string()),
            ],
        );
    }

    pub fn record_backend_error(&self, backend: &str, error_type: &str, route: &str) {
        self.backend_errors_total.add(
            1,
            &[
                KeyValue::new(labels::BACKEND_ADDRESS, backend.to_string()),
                KeyValue::new(labels::ERROR_TYPE, error_type.to_string()),
                KeyValue::new(labels::ROUTE, route.to_string()),
            ],
        );
    }

    pub fn record_request(&self, method: &str, status_code: u16, protocol: &str, route: &str) {
        self.requests_total.add(
            1,
            &[
                KeyValue::new(labels::METHOD, method.to_string()),
                KeyValue::new(labels::STATUS_CODE, status_code.to_string()),
                KeyValue::new(labels::PROTOCOL, protocol.to_string()),
                KeyValue::new(labels::ROUTE, route.to_string()),
            ],
        );
    }

    pub fn record_request_duration(
        &self,
        duration: f64,
        method: &str,
        status_code: u16,
        protocol: &str,
        route: &str,
    ) {
        self.requests_duration_seconds.record(
            duration,
            &[
                KeyValue::new(labels::METHOD, method.to_string()),
                KeyValue::new(labels::STATUS_CODE, status_code.to_string()),
                KeyValue::new(labels::PROTOCOL, protocol.to_string()),
                KeyValue::new(labels::ROUTE, route.to_string()),
            ],
        );
    }

    pub fn record_tls_handshake(&self, tls_version: &str, cipher_suite: &str, duration: f64) {
        self.tls_handshakes_total.add(
            1,
            &[
                KeyValue::new(labels::TLS_VERSION, tls_version.to_string()),
                KeyValue::new(labels::CIPHER_SUITE, cipher_suite.to_string()),
            ],
        );
        self.tls_handshake_duration_seconds.record(
            duration,
            &[
                KeyValue::new(labels::TLS_VERSION, tls_version.to_string()),
                KeyValue::new(labels::CIPHER_SUITE, cipher_suite.to_string()),
            ],
        );
    }

    pub fn record_tls_connection_active(&self) {
        self.tls_connections_active.add(1, &[]);
    }

    pub fn record_mtls_connection(&self, protocol: &str) {
        self.mtls_connections_total
            .add(1, &[KeyValue::new(labels::PROTOCOL, protocol.to_string())]);
    }

    pub fn record_error(&self, error_type: &str) {
        self.errors_total
            .add(1, &[KeyValue::new(labels::ERROR_TYPE, error_type.to_string())]);
    }

    pub fn record_tls_handshake_error(&self) {
        self.tls_handshake_errors_total.add(1, &[]);
    }

    pub fn record_timeout(&self, timeout_type: &str) {
        self.timeouts_total
            .add(1, &[KeyValue::new(labels::TIMEOUT_TYPE, timeout_type.to_string())]);
    }

    pub fn record_backend_selection(&self, backend: &str) {
        self.backend_selections_total
            .add(1, &[KeyValue::new(labels::BACKEND, backend.to_string())]);
    }

    /// Record a TCP SYN fingerprint lookup result and its duration.
    ///
    /// `result` is one of:
    /// - `"hit"`       - fingerprint found and injected (`SynResult::Hit`)
    /// - `"miss"`      - no BPF map entry (keep-alive reuse, IPv6 peer, stale)
    /// - `"malformed"` - BPF map entry present but TCP options bytes were undecodable
    pub fn record_tcp_syn_fingerprint(&self, result: &str, duration_secs: f64) {
        let attrs = &[KeyValue::new(labels::REASON, result.to_string())];
        self.tcp_syn_fingerprints_total.add(1, attrs);
        self.tcp_syn_fingerprint_duration_seconds
            .record(duration_secs, attrs);
        if result == "malformed" {
            self.tcp_syn_fingerprint_failures_total.add(1, &[]);
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

    metrics.set_build_info();

    Ok((metrics, registry))
}
