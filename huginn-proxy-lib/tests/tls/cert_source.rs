use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::helpers::{create_valid_test_cert, generate_dummy_test_cert_der};
use huginn_proxy_lib::config::{ClientAuth, TlsConfig, TlsOptions};
use huginn_proxy_lib::tls::{
    build_server_config, setup_tls_with_hot_reload, CertSource, ServerCertsKeys, StaticCertSource,
    WatchedCertSource,
};

#[tokio::test]
async fn static_cert_source_loads_valid_certs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let result = StaticCertSource::load(&cert_path, &key_path).await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let source = CertSource::Static(result?);

    assert!(
        source.subscribe().is_none(),
        "static sources must not expose a subscription channel"
    );
    let snapshot = source.current();
    assert!(!snapshot.certs.is_empty(), "static source should expose loaded certificates");

    Ok(())
}

#[tokio::test]
async fn watched_cert_source_loads_valid_certs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let result = WatchedCertSource::watch(cert_path.clone(), key_path.clone(), 60).await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let source = CertSource::Watched(result?);

    assert!(
        source.subscribe().is_some(),
        "watched sources must expose a subscription channel"
    );
    let snapshot = source.current();
    let alpn = vec!["h2".to_string()];
    let options = TlsOptions::default();
    let server = build_server_config(
        snapshot.certs.clone(),
        snapshot.key.clone_key(),
        &alpn,
        &options,
        &ClientAuth::Disabled,
        &Default::default(),
    );
    assert!(server.is_ok(), "build_server_config should succeed on watched snapshot");

    Ok(())
}

#[tokio::test]
async fn static_cert_source_missing_files_errors(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = StaticCertSource::load(
        std::path::Path::new("/nonexistent/cert.pem"),
        std::path::Path::new("/nonexistent/key.pem"),
    )
    .await;
    assert!(result.is_err(), "missing files must error");
    Ok(())
}

#[tokio::test]
async fn watched_cert_source_missing_files_errors(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = WatchedCertSource::watch(
        PathBuf::from("/nonexistent/cert.pem"),
        PathBuf::from("/nonexistent/key.pem"),
        60,
    )
    .await;
    assert!(result.is_err(), "missing files must error");
    Ok(())
}

#[tokio::test]
async fn watcher_updates_receiver_when_cert_files_change(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let source = WatchedCertSource::watch(cert_path.clone(), key_path.clone(), 1).await?;
    let source = CertSource::Watched(source);
    let mut rx = source
        .subscribe()
        .ok_or("watched source must expose subscription")?;
    let initial = source.current();

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, signing_key.serialize_pem())?;

    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if rx.changed().await.is_err() {
                return Err("watcher channel closed before cert changed");
            }
            let current = rx.borrow().clone();
            if *current != *initial {
                return Ok(());
            }
        }
    })
    .await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    match outcome {
        Err(_) => Err("cert reload did not happen within 5 seconds".into()),
        Ok(Err(e)) => Err(e.into()),
        Ok(Ok(())) => Ok(()),
    }
}

/// `StaticCertSource::subscribe()` returning `None` is the contract that
/// guarantees `setup_tls_with_hot_reload` does not spawn a reload task in
/// static mode. Together with `setup_tls_static_no_spurious_reloads` below
/// this guards against regressing the issue #211 spin-loop.
#[tokio::test]
async fn static_source_does_not_expose_subscription(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let source = StaticCertSource::load(&cert_path, &key_path).await?;
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(CertSource::Static(source).subscribe().is_none());
    Ok(())
}

#[tokio::test]
async fn setup_tls_static_no_spurious_reloads(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let setup = setup_tls_with_hot_reload(&config, false, 1).await?;
    let initial_ptr = Arc::as_ptr(&setup.acceptor.load());

    tokio::time::sleep(Duration::from_millis(300)).await;

    let final_ptr = Arc::as_ptr(&setup.acceptor.load());

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert_eq!(
        initial_ptr, final_ptr,
        "acceptor must not be swapped in static mode — spurious reloads detected"
    );
    Ok(())
}

#[test]
fn build_server_config_rejects_invalid_certs(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert, key) = generate_dummy_test_cert_der();
    let server_certs_keys = ServerCertsKeys { certs: vec![cert], key };
    let alpn = vec!["h2".to_string()];
    let options = TlsOptions::default();

    let result = build_server_config(
        server_certs_keys.certs.clone(),
        server_certs_keys.key.clone_key(),
        &alpn,
        &options,
        &ClientAuth::Disabled,
        &Default::default(),
    );
    assert!(result.is_err(), "dummy DER bytes must fail to build a ServerConfig");
    Ok(())
}
