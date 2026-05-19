use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::level_filters::LevelFilter;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

pub struct OpentelemetryConfig {
    endpoint: String,
    tracer_name: String,
    resource_name: String,
    /// Log level for OTEL
    log_level: Level,
    /// Log level of opentelemetry_sdk
    sdk_log_level: Level,
    // TODO: more options like proto, timeouts...
}

fn build_env_filter(app_level: Level, sdk_level: Level) -> EnvFilter {
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{app_level},opentelemetry={sdk_level}")))
}

impl OpentelemetryConfig {
    pub fn new(
        endpoint: String,
        tracer_name: String,
        resource_name: String,
        log_level: Level,
        sdk_log_level: Level,
    ) -> Self {
        Self { endpoint, tracer_name, resource_name, log_level, sdk_log_level }
    }
}

fn fmt_layer<S>(show_target: bool, log_level: Level) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_target(show_target)
        .with_filter(LevelFilter::from_level(log_level))
}

pub fn init_tracing_stdout(log_level: Level, show_target: bool) -> TracingGuard {
    tracing_subscriber::registry()
        .with(build_env_filter(log_level, Level::ERROR))
        .with(fmt_layer(show_target, log_level))
        .init();
    TracingGuard { otel_provider: None }
}

// In future if we will be able to log to files will holds guards to files
/// Logger guard, shutdown method should be called on exit
#[derive(Debug, Default)]
pub struct TracingGuard {
    otel_provider: Option<SdkTracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        if let Some(ref p) = self.otel_provider {
            if let Err(e) = p.force_flush() {
                eprintln!("otel tracer flush error: {e}");
            }
            if let Err(e) = p.shutdown() {
                eprintln!("otel tracer shutdown error: {e}");
            }
        }
    }
}

impl TracingGuard {
    pub fn with_otel(otel_provider: SdkTracerProvider) -> Self {
        Self { otel_provider: Some(otel_provider) }
    }
}

/// Initialize tracing with OpenTelemetry integration
pub fn init_tracing_otel(
    log_level: Level,
    show_target: bool,
    otel_config: OpentelemetryConfig,
) -> Result<TracingGuard, Box<dyn std::error::Error + Send + Sync>> {
    let exporter = opentelemetry_otlp::SpanExporterBuilder::new()
        .with_http()
        .with_endpoint(otel_config.endpoint)
        .build()?;

    let provider = SdkTracerProvider::builder()
        .with_resource(
            Resource::builder()
                .with_service_name(otel_config.resource_name)
                .build(),
        )
        .with_batch_exporter(exporter)
        .build();

    let tracer = global::tracer(otel_config.tracer_name);

    // TODO: make log_level work for internal otel library logs
    let otel_layer = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_filter(LevelFilter::from_level(otel_config.log_level));

    tracing_subscriber::registry()
        .with(build_env_filter(log_level, otel_config.sdk_log_level))
        .with(fmt_layer(show_target, log_level))
        .with(otel_layer)
        .init();

    Ok(TracingGuard::with_otel(provider))
}
