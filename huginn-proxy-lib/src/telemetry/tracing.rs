use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

/// Initialize tracing with OpenTelemetry integration
pub fn init_tracing_with_otel(
    log_level: String,
    show_target: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // For now, we'll use a simple fmt subscriber
    // OpenTelemetry tracing can be added later when we need full trace export
    // The metrics are already set up separately via init_metrics()

    let env_filter = tracing_subscriber::EnvFilter::new(log_level);
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
