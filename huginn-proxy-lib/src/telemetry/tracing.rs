use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

/// Targets silenced by default because they log client-controlled input as failures.
///
/// `huginn-net-tls` emits `ERROR TLS plaintext parsing failed` for every HTTP request or
/// stray byte that reaches the TLS port (JA4 parse), which is client noise rather than a
/// proxy fault.
const QUIET_TARGETS: &str = "huginn_net_tls=off";

/// Compose the log filter used when `RUST_LOG` is unset.
///
/// `RUST_LOG` replaces this string wholesale, which is the escape hatch for the targets in
/// [`QUIET_TARGETS`]: `RUST_LOG=info,huginn_net_tls=debug` brings those events back.
pub fn default_log_filter(base: &str) -> String {
    format!("{base},{QUIET_TARGETS}")
}

/// Initialize warning-level tracing for one-shot CLI validation.
///
/// Diagnostics go to stderr so stdout remains valid machine-readable output when printing the
/// effective configuration.
pub fn init_validation_tracing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_log_filter("warn")));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr);
    let subscriber = Registry::default().with(env_filter).with(fmt_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| format!("Failed to set validation tracing subscriber: {e}"))?;
    Ok(())
}

/// Initialize tracing with OpenTelemetry integration
pub fn init_tracing_with_otel(
    log_level: String,
    show_target: bool,
    otel_log_level: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter_str = default_log_filter(&format!("{log_level},opentelemetry={otel_log_level}"));
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
