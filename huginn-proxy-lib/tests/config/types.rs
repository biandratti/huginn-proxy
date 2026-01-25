use huginn_proxy_lib::config::{Backend, BackendHttpVersion, ClientAuth, Config, TlsConfig};

#[test]
fn test_backend_http_version_deserialization(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"address = "backend:9000"
http_version = "http11""#;
    let backend: Backend = toml::from_str(toml)?;
    assert_eq!(backend.http_version, Some(BackendHttpVersion::Http11));

    let toml = r#"address = "backend:9000"
http_version = "http2""#;
    let backend: Backend = toml::from_str(toml)?;
    assert_eq!(backend.http_version, Some(BackendHttpVersion::Http2));

    let toml = r#"address = "backend:9000"
http_version = "preserve""#;
    let backend: Backend = toml::from_str(toml)?;
    assert_eq!(backend.http_version, Some(BackendHttpVersion::Preserve));

    let toml = r#"address = "backend:9000""#;
    let backend: Backend = toml::from_str(toml)?;
    assert_eq!(backend.http_version, None);
    Ok(())
}

#[test]
fn test_config_with_http_version() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = "127.0.0.1:0"
backends = [
  { address = "backend-a:9000", http_version = "http2" },
  { address = "backend-b:9000", http_version = "http11" },
  { address = "backend-c:9000", http_version = "preserve" },
  { address = "backend-d:9000" }
]
"#;

    let config: Config = toml::from_str(toml)?;
    assert_eq!(config.backends.len(), 4);
    assert_eq!(config.backends[0].http_version, Some(BackendHttpVersion::Http2));
    assert_eq!(config.backends[1].http_version, Some(BackendHttpVersion::Http11));
    assert_eq!(config.backends[2].http_version, Some(BackendHttpVersion::Preserve));
    assert_eq!(config.backends[3].http_version, None);
    Ok(())
}

#[test]
fn test_backend_http_version_case_insensitive() {
    let toml = r#"address = "backend:9000"
http_version = "HTTP11""#;
    assert!(toml::from_str::<Backend>(toml).is_err());
}

#[test]
fn test_mtls_config_required() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
cert_path = "/config/certs/server.crt"
key_path = "/config/certs/server.key"
alpn = ["h2", "http/1.1"]
watch_delay_secs = 60

[client_auth]
required = { ca_cert_path = "/config/certs/client-ca.crt" }
"#;

    let config: TlsConfig = toml::from_str(toml)?;
    match config.client_auth {
        ClientAuth::Required { ca_cert_path } => {
            assert_eq!(ca_cert_path, "/config/certs/client-ca.crt");
        }
        ClientAuth::Disabled => panic!("Expected ClientAuth::Required"),
    }
    Ok(())
}

#[test]
fn test_mtls_config_default_is_disabled() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
cert_path = "/config/certs/server.crt"
key_path = "/config/certs/server.key"
alpn = ["h2", "http/1.1"]
watch_delay_secs = 60
"#;

    let config: TlsConfig = toml::from_str(toml)?;
    assert!(matches!(config.client_auth, ClientAuth::Disabled));
    Ok(())
}

#[test]
fn test_mtls_full_config() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = "0.0.0.0:7000"

backends = [
  { address = "backend-a:9000" }
]

routes = [
  { prefix = "/api", backend = "backend-a:9000" }
]

[tls]
cert_path = "/config/certs/server.crt"
key_path = "/config/certs/server.key"
alpn = ["h2", "http/1.1"]
watch_delay_secs = 60

[tls.client_auth]
required = { ca_cert_path = "/config/certs/client-ca.crt" }
"#;

    let config: Config = toml::from_str(toml)?;

    let Some(tls_config) = config.tls else {
        panic!("Expected TLS config to be present");
    };

    match tls_config.client_auth {
        ClientAuth::Required { ca_cert_path } => {
            assert_eq!(ca_cert_path, "/config/certs/client-ca.crt");
        }
        ClientAuth::Disabled => panic!("Expected ClientAuth::Required"),
    }
    Ok(())
}

#[test]
fn test_preserve_host_default_is_false() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = "0.0.0.0:7000"
backends = [{ address = "backend:9000" }]
"#;

    let config: Config = toml::from_str(toml)?;
    assert!(!config.preserve_host);
    Ok(())
}

#[test]
fn test_preserve_host_enabled() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = "0.0.0.0:7000"
backends = [{ address = "backend:9000" }]
preserve_host = true
"#;

    let config: Config = toml::from_str(toml)?;
    assert!(config.preserve_host);
    Ok(())
}

#[test]
fn test_preserve_host_disabled_explicitly() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let toml = r#"
listen = "0.0.0.0:7000"
backends = [{ address = "backend:9000" }]
preserve_host = false
"#;

    let config: Config = toml::from_str(toml)?;
    assert!(!config.preserve_host);
    Ok(())
}

#[test]
fn test_timeout_defaults() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = "0.0.0.0:7000"
backends = [{ address = "backend:9000" }]
"#;

    let config: Config = toml::from_str(toml)?;
    assert_eq!(config.timeout.connect_ms, 5000);
    assert_eq!(config.timeout.idle_ms, 60000);
    assert_eq!(config.timeout.shutdown_secs, 30);
    assert_eq!(config.timeout.tls_handshake_secs, 15);
    assert_eq!(config.timeout.connection_handling_secs, 300);
    Ok(())
}

#[test]
fn test_timeout_granular_config() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = "0.0.0.0:7000"
backends = [{ address = "backend:9000" }]

[timeout]
tls_handshake_secs = 20
connection_handling_secs = 120
"#;

    let config: Config = toml::from_str(toml)?;
    assert_eq!(config.timeout.tls_handshake_secs, 20);
    assert_eq!(config.timeout.connection_handling_secs, 120);
    Ok(())
}

#[test]
fn test_timeout_connection_handling_default() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let toml = r#"
listen = "0.0.0.0:7000"
backends = [{ address = "backend:9000" }]

[timeout]
tls_handshake_secs = 15
"#;

    let config: Config = toml::from_str(toml)?;
    assert_eq!(config.timeout.connection_handling_secs, 300); // default value
    Ok(())
}
