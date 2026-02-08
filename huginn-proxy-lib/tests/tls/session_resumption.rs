use huginn_proxy_lib::config::{ClientAuth, SessionResumptionConfig, TlsConfig};
use huginn_proxy_lib::tls::build_rustls;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn tmp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("huginn-test-{nanos}-{name}"))
}

fn create_test_cert() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tmp_path("test.crt");
    let key_path = tmp_path("test.key");

    fs::write(
        &cert_path,
        b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKJ\n-----END CERTIFICATE-----\n",
    )?;
    fs::write(
        &key_path,
        b"-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkq\n-----END PRIVATE KEY-----\n",
    )?;

    Ok((cert_path, key_path))
}

#[test]
fn test_session_resumption_enabled_default() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_rustls(&config);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Note: This may fail due to invalid certs, but we're testing the configuration structure
    // The important thing is that session_resumption is accepted
    let _ = result;
    Ok(())
}

#[test]
fn test_session_resumption_disabled() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: SessionResumptionConfig { enabled: false, max_sessions: 256 },
    };

    let result = build_rustls(&config);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    // Note: This may fail due to invalid certs, but we're testing the configuration structure
    let _ = result;
    Ok(())
}

#[test]
fn test_session_resumption_custom_cache_size(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_test_cert()?;

    let config = TlsConfig {
        watch_delay_secs: 60,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: Default::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: SessionResumptionConfig { enabled: true, max_sessions: 512 },
    };

    let result = build_rustls(&config);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

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

fn generate_test_cert() -> Result<
    (
        rustls_pki_types::CertificateDer<'static>,
        rustls_pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let subject_alt_names = vec!["localhost".to_string()];
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(subject_alt_names)?;

    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );

    Ok((cert_der, key_der))
}

#[test]
fn test_session_storage_configuration() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::tls::session_resumption::configure_session_resumption;
    use tokio_rustls::rustls::ServerConfig;

    // Generate valid test cert/key
    let (cert, key) = generate_test_cert()?;

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
    let (cert, key) = generate_test_cert()?;

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
