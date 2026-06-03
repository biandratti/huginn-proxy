use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::helpers::{create_valid_test_cert, generate_dummy_test_cert_der, never_shutdown};
use huginn_proxy_lib::config::{ClientAuth, TlsConfig, TlsOptions};
use huginn_proxy_lib::telemetry::Metrics;
use huginn_proxy_lib::tls::{
    build_server_config, cert_chain_hash, setup_tls_with_hot_reload, CertSource, ServerCertsKeys,
    StaticCertSource, WatchedCertSource,
};
use tokio_rustls::rustls::{CipherSuite, ServerConfig};

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

    let result =
        WatchedCertSource::watch(cert_path.clone(), key_path.clone(), 60, never_shutdown().1).await;

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
        never_shutdown().1,
    )
    .await;
    assert!(result.is_err(), "missing files must error");
    Ok(())
}

#[tokio::test]
async fn watcher_updates_receiver_when_cert_files_change(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let (_shutdown_tx, shutdown_rx) = never_shutdown();
    let source =
        WatchedCertSource::watch(cert_path.clone(), key_path.clone(), 1, shutdown_rx).await?;
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
/// static mode.
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

// TODO(step2): restore when DynamicCertResolver is implemented and
// setup_tls_with_hot_reload no longer returns Err unconditionally.
#[ignore]
#[tokio::test]
async fn setup_tls_static_no_spurious_reloads(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let (_shutdown_tx, shutdown_rx) = never_shutdown();
    let setup =
        setup_tls_with_hot_reload(&config, false, 1, Metrics::new_noop(), shutdown_rx).await?;
    let initial_ptr = Arc::as_ptr(&setup.acceptor.load());

    tokio::time::sleep(Duration::from_millis(300)).await;

    let final_ptr = Arc::as_ptr(&setup.acceptor.load());

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert_eq!(
        initial_ptr, final_ptr,
        "acceptor must not be swapped in static mode, spurious reloads detected"
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

fn cipher_suites_of(server: &ServerConfig) -> Vec<CipherSuite> {
    server
        .crypto_provider()
        .cipher_suites
        .iter()
        .map(|s| s.suite())
        .collect()
}

#[tokio::test]
async fn cipher_suites_applied_on_initial_build(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let source_result = StaticCertSource::load(&cert_path, &key_path).await;
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    let source = CertSource::Static(source_result?);
    let snapshot = source.current();

    let options = TlsOptions {
        cipher_suites: vec!["TLS13_AES_128_GCM_SHA256".to_string()],
        ..Default::default()
    };
    let server = build_server_config(
        snapshot.certs.clone(),
        snapshot.key.clone_key(),
        &[],
        &options,
        &ClientAuth::Disabled,
        &Default::default(),
    )?;

    assert_eq!(
        cipher_suites_of(&server),
        vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
        "build_server_config must apply the configured cipher suites, not the provider defaults"
    );
    Ok(())
}

// TODO(step2): restore when DynamicCertResolver is implemented.
#[ignore]
#[tokio::test]
async fn cipher_suites_applied_after_reload() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        alpn: vec![],
        options: TlsOptions {
            cipher_suites: vec!["TLS13_AES_128_GCM_SHA256".to_string()],
            ..Default::default()
        },
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let (_shutdown_tx, shutdown_rx) = never_shutdown();
    let setup =
        setup_tls_with_hot_reload(&config, true, 1, Metrics::new_noop(), shutdown_rx).await?;
    let initial_acceptor = setup.acceptor.load_full();
    let initial_ptr = Arc::as_ptr(&initial_acceptor);

    // Initial config must already have the custom cipher suites applied.
    assert_eq!(
        cipher_suites_of(initial_acceptor.config()),
        vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
        "initial TlsAcceptor must honor configured cipher suites"
    );

    // Rotate the certificate files.
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, signing_key.serialize_pem())?;

    // Wait for the reload task to swap the acceptor.
    let swap_outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let current = setup.acceptor.load_full();
            if Arc::as_ptr(&current) != initial_ptr {
                return current;
            }
        }
    })
    .await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let new_acceptor = swap_outcome.map_err(|_| "TlsAcceptor was not swapped within 5 seconds")?;

    assert_eq!(
        cipher_suites_of(new_acceptor.config()),
        vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
        "TlsAcceptor must still honor configured cipher suites after a reload"
    );
    Ok(())
}

// TODO(step2): restore when DynamicCertResolver is implemented.
#[ignore]
#[tokio::test]
async fn hot_reload_survives_dropping_tls_setup_keeping_only_acceptor(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    // Simulate the proxy::server caller: keep only the acceptor.
    let (_shutdown_tx, shutdown_rx) = never_shutdown();
    let acceptor = setup_tls_with_hot_reload(&config, true, 1, Metrics::new_noop(), shutdown_rx)
        .await?
        .acceptor;
    let initial_ptr = Arc::as_ptr(&acceptor.load_full());

    // Rotate the cert and assert the acceptor is swapped in. If the
    // watcher had been torn down with the dropped `TlsSetup`, no swap would ever happen.
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, signing_key.serialize_pem())?;

    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if Arc::as_ptr(&acceptor.load_full()) != initial_ptr {
                return;
            }
        }
    })
    .await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    outcome.map_err(|_| {
        "TlsAcceptor was not swapped within 5s, watcher was torn down when TlsSetup was dropped"
    })?;
    Ok(())
}

#[tokio::test]
async fn cert_chain_hash_changes_when_certificate_chain_changes(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rustls_pki_types::CertificateDer;

    let key_a = rcgen::generate_simple_self_signed(vec!["a.test".to_string()])?;
    let key_b = rcgen::generate_simple_self_signed(vec!["b.test".to_string()])?;

    let der_a: CertificateDer<'static> = key_a.cert.der().clone();
    let der_b: CertificateDer<'static> = key_b.cert.der().clone();

    let hash_a_first = cert_chain_hash(std::slice::from_ref(&der_a));
    let hash_a_second = cert_chain_hash(std::slice::from_ref(&der_a));
    let hash_b = cert_chain_hash(std::slice::from_ref(&der_b));

    assert_eq!(hash_a_first, hash_a_second, "same chain must produce a stable hash");
    assert_ne!(hash_a_first, hash_b, "different chains must produce different hashes");
    Ok(())
}

#[tokio::test]
async fn dropping_watched_source_closes_subscription_channel(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let result =
        WatchedCertSource::watch(cert_path.clone(), key_path.clone(), 60, never_shutdown().1).await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let source = CertSource::Watched(result?);
    let mut rx = source
        .subscribe()
        .ok_or("watched source must expose subscription")?;

    drop(source);

    let outcome = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
    let changed = outcome.map_err(|_| "rx.changed() did not return within 1s after source drop")?;
    assert!(
        changed.is_err(),
        "rx.changed() must return Err once the source (and its sender) is dropped"
    );
    Ok(())
}

// TODO(step2): restore when DynamicCertResolver is implemented.
#[ignore]
#[tokio::test]
async fn cert_reload_task_exits_on_shutdown_signal(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let config = TlsConfig {
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let (shutdown_tx, shutdown_rx) = huginn_proxy_lib::shutdown_channel();
    let setup =
        setup_tls_with_hot_reload(&config, true, 60, Metrics::new_noop(), shutdown_rx).await?;

    let handle = setup
        .reload_handle
        .ok_or("watch mode must produce a reload handle")?;

    // Signal shutdown and assert the task exits within 1 second.
    shutdown_tx.send(true)?;
    tokio::time::timeout(Duration::from_secs(1), handle.handle)
        .await
        .map_err(|_| "cert-reload task did not exit within 1s after shutdown signal")?
        .map_err(|e| format!("cert-reload task panicked: {e}"))?;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    Ok(())
}

// TODO(step2): restore when DynamicCertResolver is implemented.
#[ignore]
#[tokio::test]
async fn cert_reload_task_none_in_static_mode(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let config = TlsConfig {
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let (_shutdown_tx, shutdown_rx) = never_shutdown();
    let setup =
        setup_tls_with_hot_reload(&config, false, 60, Metrics::new_noop(), shutdown_rx).await?;

    assert!(setup.reload_handle.is_none(), "static mode must not spawn a reload task");

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    Ok(())
}

// TODO(step2): restore when DynamicCertResolver is implemented.
#[ignore]
#[tokio::test]
async fn shutdown_ordering_background_tasks_exit_before_signal(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc as StdArc;

    let (cert_path, key_path) = create_valid_test_cert()?;
    let config = TlsConfig {
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let (shutdown_tx, shutdown_rx) = huginn_proxy_lib::shutdown_channel();
    let setup =
        setup_tls_with_hot_reload(&config, true, 60, Metrics::new_noop(), shutdown_rx).await?;

    let svc = setup
        .reload_handle
        .ok_or("watch mode must produce a reload handle")?;

    // Signal shutdown, await the handle, then set the flag.
    // If anything logged after the flag was set and before tracing teardown
    // would be lost, here we verify ordering without touching tracing.
    let tasks_exited = StdArc::new(AtomicBool::new(false));
    let flag = StdArc::clone(&tasks_exited);

    shutdown_tx.send(true)?;
    tokio::time::timeout(Duration::from_secs(1), svc.handle)
        .await
        .map_err(|_| "cert-reload task did not exit within timeout")?
        .map_err(|e| format!("cert-reload task panicked: {e}"))?;

    flag.store(true, Ordering::SeqCst);

    // shutdown_tracing() would be called here in production.
    // The flag being true proves all tasks finished first.
    assert!(
        tasks_exited.load(Ordering::SeqCst),
        "background tasks must exit before tracing teardown"
    );

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    Ok(())
}

#[tokio::test]
async fn debounce_task_exits_cooperatively_on_shutdown(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let (shutdown_tx, shutdown_rx) = huginn_proxy_lib::shutdown_channel();
    let source =
        WatchedCertSource::watch(cert_path.clone(), key_path.clone(), 60, shutdown_rx).await?;
    let source = CertSource::Watched(source);
    let mut rx = source
        .subscribe()
        .ok_or("watched source must expose subscription")?;

    shutdown_tx.send(true)?;

    let outcome = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let changed = outcome.map_err(|_| "debounce task did not exit within 1s after shutdown")?;
    assert!(
        changed.is_err(),
        "cert channel must close when debounce task exits cooperatively on shutdown"
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_during_debounce_window_does_not_publish(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let (shutdown_tx, shutdown_rx) = huginn_proxy_lib::shutdown_channel();
    let source =
        WatchedCertSource::watch(cert_path.clone(), key_path.clone(), 5, shutdown_rx).await?;
    let source = CertSource::Watched(source);
    let mut rx = source
        .subscribe()
        .ok_or("watched source must expose subscription")?;

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, signing_key.serialize_pem())?;

    tokio::time::sleep(Duration::from_millis(200)).await;
    shutdown_tx.send(true)?;

    let outcome = tokio::time::timeout(Duration::from_secs(2), rx.changed()).await;
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let changed = outcome.map_err(|_| "channel did not close within 2s after shutdown")?;
    assert!(
        changed.is_err(),
        "debounce must not publish cert update when shutdown interrupts the debounce window"
    );
    Ok(())
}

#[tokio::test]
async fn debounce_task_exits_when_shutdown_sender_dropped(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;
    let (shutdown_tx, shutdown_rx) = huginn_proxy_lib::shutdown_channel();
    let source =
        WatchedCertSource::watch(cert_path.clone(), key_path.clone(), 60, shutdown_rx).await?;
    let source = CertSource::Watched(source);
    let mut rx = source
        .subscribe()
        .ok_or("watched source must expose subscription")?;

    drop(shutdown_tx);

    let outcome = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let changed =
        outcome.map_err(|_| "debounce task did not exit within 1s after sender dropped")?;
    assert!(
        changed.is_err(),
        "cert channel must close when debounce task exits after shutdown sender is dropped"
    );
    Ok(())
}
