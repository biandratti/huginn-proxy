use huginn_proxy_lib::config::{
    load_from_path, Backend, Config, FingerprintConfig, LoggingConfig, TelemetryConfig,
    TimeoutConfig,
};
use std::io::Write;
use tempfile::NamedTempFile;

fn create_test_config(listen: &str, backends: Vec<Backend>) -> Config {
    Config {
        listen: listen
            .parse()
            .unwrap_or_else(|_| panic!("Invalid listen address: {listen}")),
        backends,
        routes: vec![],
        tls: None,
        fingerprint: FingerprintConfig { tls_enabled: true, http_enabled: true },
        logging: LoggingConfig { level: "info".to_string(), show_target: false },
        timeout: TimeoutConfig { connect_ms: 5000, idle_ms: 60000, shutdown_secs: 30 },
        telemetry: TelemetryConfig { metrics_port: None, otel_log_level: "warn".to_string() },
    }
}

#[tokio::test]
async fn test_config_loads_valid_file() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"
listen = "127.0.0.1:0"
backends = [
    {{ address = "localhost:9000" }}
]
"#
    )?;

    let config = load_from_path(file.path())?;
    assert_eq!(config.listen.to_string(), "127.0.0.1:0");
    assert_eq!(config.backends.len(), 1);
    assert_eq!(config.backends[0].address, "localhost:9000");

    Ok(())
}

#[tokio::test]
async fn test_config_with_routes() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"
listen = "127.0.0.1:0"
backends = [
    {{ address = "backend-a:9000" }},
    {{ address = "backend-b:9000" }}
]
routes = [
    {{ prefix = "/api", backend = "backend-a:9000" }},
    {{ prefix = "/", backend = "backend-b:9000" }}
]
"#
    )?;

    let config = load_from_path(file.path())?;
    assert_eq!(config.routes.len(), 2);
    assert_eq!(config.routes[0].prefix, "/api");
    assert_eq!(config.routes[0].backend, "backend-a:9000");
    assert_eq!(config.routes[1].prefix, "/");
    assert_eq!(config.routes[1].backend, "backend-b:9000");

    Ok(())
}

#[test]
fn test_config_defaults() {
    let config = create_test_config("127.0.0.1:0", vec![]);

    assert!(config.fingerprint.tls_enabled);
    assert!(config.fingerprint.http_enabled);
    assert_eq!(config.logging.level, "info");
    assert!(!config.logging.show_target);
    assert_eq!(config.timeout.connect_ms, 5000);
    assert_eq!(config.timeout.idle_ms, 60000);
    assert_eq!(config.timeout.shutdown_secs, 30);
}

#[test]
fn test_config_with_fingerprinting() {
    let mut config = create_test_config("127.0.0.1:0", vec![]);
    config.fingerprint.tls_enabled = true;
    config.fingerprint.http_enabled = true;

    assert!(config.fingerprint.tls_enabled);
    assert!(config.fingerprint.http_enabled);
}

#[test]
fn test_config_with_custom_timeouts() {
    let mut config = create_test_config("127.0.0.1:0", vec![]);
    config.timeout.connect_ms = 10000;
    config.timeout.idle_ms = 120000;
    config.timeout.shutdown_secs = 60;

    assert_eq!(config.timeout.connect_ms, 10000);
    assert_eq!(config.timeout.idle_ms, 120000);
    assert_eq!(config.timeout.shutdown_secs, 60);
}
