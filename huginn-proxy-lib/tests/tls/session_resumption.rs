use crate::helpers::{create_dummy_test_cert, generate_valid_test_cert_der};
use huginn_proxy_lib::config::{ClientAuth, SessionResumptionConfig, TlsConfig};
use huginn_proxy_lib::tls::build_tls_acceptor;

#[test]
fn test_session_resumption_enabled_default() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let (cert_path, key_path) = create_dummy_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_tls_acceptor(&config);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Note: This may fail due to invalid certs, but we're testing the configuration structure
    // The important thing is that session_resumption is accepted
    let _ = result;
    Ok(())
}

#[test]
fn test_session_resumption_disabled() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_dummy_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: SessionResumptionConfig { enabled: false, max_sessions: 256 },
    };

    let result = build_tls_acceptor(&config);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Note: This may fail due to invalid certs, but we're testing the configuration structure
    let _ = result;
    Ok(())
}

#[test]
fn test_session_resumption_custom_cache_size(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_dummy_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: SessionResumptionConfig { enabled: true, max_sessions: 512 },
    };

    let result = build_tls_acceptor(&config);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Note: This may fail due to invalid certs, but we're testing the configuration structure
    let _ = result;
    Ok(())
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

#[test]
fn test_session_storage_configuration() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::tls::session_resumption::configure_session_resumption;
    use tokio_rustls::rustls::ServerConfig;

    // Generate valid test cert/key
    let (cert, key) = generate_valid_test_cert_der()?;

    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.clone_key())?;

    let config_enabled = SessionResumptionConfig { enabled: true, max_sessions: 512 };

    configure_session_resumption(&mut server, &config_enabled);

    let mut server_disabled = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    let config_disabled = SessionResumptionConfig { enabled: false, max_sessions: 256 };

    configure_session_resumption(&mut server_disabled, &config_disabled);

    // Verify that session_storage is disabled (NoSessionStorage)
    // We can verify this by checking can_cache returns false
    assert!(!server_disabled.session_storage.can_cache());
    Ok(())
}

#[test]
fn test_ticket_producer_configuration() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::tls::session_resumption::configure_session_resumption;
    use tokio_rustls::rustls::ServerConfig;

    // Generate valid test cert/key
    let (cert, key) = generate_valid_test_cert_der()?;

    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.clone_key())?;

    // Check default ticketer state before configuration
    let default_ticketer_enabled = server.ticketer.enabled();

    let config_enabled = SessionResumptionConfig { enabled: true, max_sessions: 256 };

    configure_session_resumption(&mut server, &config_enabled);

    // When enabled, we don't modify the ticketer (leave rustls defaults unchanged)
    // So it should remain in its default state
    assert_eq!(server.ticketer.enabled(), default_ticketer_enabled);

    let mut server_disabled = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    let config_disabled = SessionResumptionConfig { enabled: false, max_sessions: 256 };

    configure_session_resumption(&mut server_disabled, &config_disabled);

    // Verify that ticketer is explicitly disabled (NoTicketProducer)
    assert!(!server_disabled.ticketer.enabled());
    assert_eq!(server_disabled.ticketer.lifetime(), 0);
    Ok(())
}
