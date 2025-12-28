use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

/// Initialize tracing with OpenTelemetry integration
pub fn init_tracing_with_otel(
    log_level: String,
    show_target: bool,
    otel_log_level: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build env filter from configuration
    // Note: log_level already includes RUST_LOG override from main.rs if set
    let filter_str = format!("{log_level},opentelemetry={otel_log_level}");
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter_str));
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(show_target);

    let subscriber = Registry::default().with(env_filter).with(fmt_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| format!("Failed to set global tracing subscriber: {e}"))?;

    Ok(())
}

/// Shutdown tracing and flush any pending logs
///
/// Currently flushes stdout/stderr to ensure all logs are written.
/// When OpenTelemetry tracing is added, this will also shutdown the tracer provider.
pub fn shutdown_tracing() {
    use std::io::Write;

    // Flush stdout and stderr to ensure all logs are written
    // This is important for logs that might be buffered
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    // TODO: When OpenTelemetry tracing is implemented, add:
    // opentelemetry::global::shutdown_tracer_provider();
}
