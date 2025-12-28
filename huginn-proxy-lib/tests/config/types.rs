use huginn_proxy_lib::config::{Backend, BackendHttpVersion, Config};

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
