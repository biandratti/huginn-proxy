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
        session_resumption: SessionResumptionConfig { enabled: false },
    };
    assert!(!config.session_resumption.enabled);
}

#[test]
fn test_session_resumption_config_defaults() {
    let config = SessionResumptionConfig::default();
    assert!(config.enabled);
}

#[test]
fn test_session_resumption_config_toml_deserialization(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deserialized: SessionResumptionConfig = toml::from_str("enabled = true\n")?;
    assert!(deserialized.enabled);
    Ok(())
}

/// `max_sessions` was removed: with `deny_unknown_fields`, a config that still
/// declares it must now fail to parse (breaking change, surfaced loudly).
#[test]
fn test_session_resumption_rejects_removed_max_sessions() {
    let result: Result<SessionResumptionConfig, _> =
        toml::from_str("enabled = true\nmax_sessions = 512\n");
    assert!(result.is_err(), "the removed `max_sessions` key must be rejected, not ignored");
}
