use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

/// Initialize tracing with OpenTelemetry integration
pub fn init_tracing_with_otel(
    log_level: String,
    show_target: bool,
    otel_log_level: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // For now, we'll use a simple fmt subscriber
    // OpenTelemetry tracing can be added later when we need full trace export
    // The metrics are already set up separately via init_metrics()

    //TODO: unified logging with otel
    // Build env filter: use RUST_LOG if set, otherwise use configured levels
    // RUST_LOG can override both the main log level and OpenTelemetry log level
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!("{log_level},opentelemetry={otel_log_level}"))
    });
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(show_target);

    let subscriber = Registry::default().with(env_filter).with(fmt_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| format!("Failed to set global tracing subscriber: {e}"))?;

    Ok(())
}

//TODO: Implement this once we have a proper implementation
/// Shutdown OpenTelemetry tracing
/// Note: Currently a no-op, but can be extended when full tracing is implemented
pub fn shutdown_tracing() {
    // No-op for now
}
