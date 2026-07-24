use huginn_proxy_lib::config::{SessionResumptionConfig, TlsConfig};

#[test]
fn test_session_resumption_enabled_default() {
    let config = TlsConfig {
        alpn: vec![],
        options: Default::default(),
        session_resumption: Default::default(),
    };
    assert!(config.session_resumption.enabled);
}

#[test]
fn test_session_resumption_disabled() {
    let config = TlsConfig {
        alpn: vec![],
        options: Default::default(),
        session_resumption: SessionResumptionConfig { enabled: false, max_sessions: 256 },
    };
    assert!(!config.session_resumption.enabled);
}

#[test]
fn test_session_resumption_custom_cache_size() {
    let config = TlsConfig {
        alpn: vec![],
        options: Default::default(),
        session_resumption: SessionResumptionConfig { enabled: true, max_sessions: 512 },
    };
    assert_eq!(config.session_resumption.max_sessions, 512);
}

#[test]
fn test_session_resumption_config_defaults() {
    let config = SessionResumptionConfig::default();

    // Verify defaults
    assert!(config.enabled);
    assert_eq!(config.max_sessions, 256);
}

#[test]
fn test_session_resumption_config_toml_deserialization(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Test TOML deserialization (config files use TOML)
    let toml_str = r#"
enabled = true
max_sessions = 512
"#;

    let deserialized: SessionResumptionConfig = toml::from_str(toml_str)?;

    assert!(deserialized.enabled);
    assert_eq!(deserialized.max_sessions, 512);
    Ok(())
}
