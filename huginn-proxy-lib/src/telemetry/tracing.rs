use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::level_filters::LevelFilter;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

pub struct OpentelemetryConfig {
    endpoint: String,
    tracer_name: String,
    resource_name: String,
    log_level: Level,
    // TODO: more options like proto, timeouts...
}

impl OpentelemetryConfig {
    pub fn new(
        endpoint: String,
        tracer_name: String,
        resource_name: String,
        log_level: Level,
    ) -> Self {
        Self { endpoint, tracer_name, resource_name, log_level }
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
        .with(fmt_layer(show_target, log_level))
        .init();
    TracingGuard { otel_provider: None }
}

#[derive(Debug, Default)]
pub struct TracingGuard {
    otel_provider: Option<SdkTracerProvider>,
}

impl TracingGuard {
    pub fn shutdown(self) {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        if let Some(p) = self.otel_provider {
            if let Err(e) = p.force_flush() {
                tracing::error!("otel tracer flush error: {e}");
            }
            if let Err(e) = p.shutdown() {
                tracing::error!("otel tracer shutdown error: {e}");
            }
        }
    }

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
        .with(fmt_layer(show_target, log_level))
        .with(otel_layer)
        .init();

    Ok(TracingGuard::with_otel(provider))
}
