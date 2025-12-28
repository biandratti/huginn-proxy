use crate::telemetry::handle_metrics;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Registry;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, warn};

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

pub async fn start_metrics_server(
    port: u16,
    registry: Registry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let registry = Arc::new(registry);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    info!(?addr, "Metrics server started on dedicated port");

    // Setup signal handlers for graceful shutdown
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .map_err(|e| std::io::Error::other(format!("Failed to setup SIGTERM handler: {e}")))?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .map_err(|e| std::io::Error::other(format!("Failed to setup SIGINT handler: {e}")))?;

    loop {
        tokio::select! {
            // Handle shutdown signals
            _ = sigterm.recv() => {
                info!("Metrics server: Received SIGTERM, shutting down");
                break;
            }
            _ = sigint.recv() => {
                info!("Metrics server: Received SIGINT, shutting down");
                break;
            }
            // Accept connections
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok((stream, peer)) => (stream, peer),
                    Err(e) => {
                        warn!(error = %e, "Metrics server: accept error");
                        continue;
                    }
                };

                let registry = registry.clone();
                tokio::spawn(async move {

                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let registry = registry.clone();
                        async move {
                            // Only serve /metrics endpoint
                            if req.uri().path() == "/metrics" {
                                match handle_metrics(&registry) {
                                    Ok(resp) => Ok::<_, hyper::Error>(resp),
                                    Err(_) => {
                                        let body = Full::new(Bytes::from("Internal Server Error"))
                                            .map_err(|never| match never {})
                                            .boxed();
                                        let mut resp = hyper::Response::new(body);
                                        *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                                        Ok(resp)
                                    }
                                }
                            } else {
                                let body = Full::new(Bytes::from("Not Found"))
                                    .map_err(|never| match never {})
                                    .boxed();
                                let mut resp = hyper::Response::new(body);
                                *resp.status_mut() = hyper::StatusCode::NOT_FOUND;
                                Ok(resp)
                            }
                        }
                    });

                    let builder = ConnBuilder::new(TokioExecutor::new());
                    if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                        warn!(?peer, error = %e, "Metrics server: serve_connection error");
                    }
                });
            }
        }
    }

    info!("Metrics server stopped");
    Ok(())
}
