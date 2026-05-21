use std::sync::Arc;
use std::time::Duration;

use crate::helpers::{create_valid_test_cert, generate_dummy_test_cert_der};
use huginn_proxy_lib::config::{ClientAuth, TlsConfig, TlsOptions};
use huginn_proxy_lib::tls::{build_cert_reloader, setup_tls_with_hot_reload};

#[tokio::test]
async fn test_build_cert_reloader() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec!["h2".to_string()],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_cert_reloader(&config, true, 60).await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let rx = match result {
        Ok(rx) => rx,
        Err(e) => panic!("build_cert_reloader should succeed with valid certificates: {e}"),
    };
    let initial_value = rx.borrow();
    let certs_keys = match initial_value.as_ref() {
        Some(certs_keys) => certs_keys,
        None => panic!("initial value should be Some"),
    };

    let alpn = vec!["h2".to_string()];
    let options = TlsOptions::default();
    let acceptor_result =
        certs_keys.build_tls_acceptor(&alpn, &options, &config.session_resumption);
    assert!(
        acceptor_result.is_ok(),
        "build_tls_acceptor should succeed with valid certificates"
    );

    Ok(())
}

#[tokio::test]
async fn test_build_cert_reloader_missing_files(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = TlsConfig {
        cert_path: "/nonexistent/cert.pem".to_string(),
        key_path: "/nonexistent/key.pem".to_string(),
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let result = build_cert_reloader(&config, true, 60).await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn watcher_updates_receiver_when_cert_files_change(
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

    let mut rx = build_cert_reloader(&config, true, 1).await?;
    let initial = rx.borrow().clone().ok_or("initial cert value was None")?;

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, signing_key.serialize_pem())?;

    match tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.changed().await {
                Err(_) => return Err("watcher channel closed before cert changed"),
                Ok(()) => {
                    if rx.borrow().clone().is_some_and(|c| c != initial) {
                        return Ok(());
                    }
                }
            }
        }
    })
    .await
    {
        Err(_) => return Err("cert reload did not happen within 5 seconds".into()),
        Ok(Err(e)) => return Err(e.into()),
        Ok(Ok(())) => {}
    }

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    Ok(())
}

/// In static mode (watch=false), the reloader should never fire `changed()`.
/// The watch sender must stay alive so that `changed()` blocks forever instead
/// of returning `Err(RecvError)` immediately and causing a spin loop.
#[tokio::test]
async fn static_reloader_no_update() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = create_valid_test_cert()?;

    let config = TlsConfig {
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        alpn: vec![],
        options: TlsOptions::default(),
        client_auth: ClientAuth::Disabled,
        session_resumption: Default::default(),
    };

    let mut rx = build_cert_reloader(&config, false, 1).await?;
    let _initial = rx.borrow().clone().ok_or("initial cert value was None")?;

    let mut counter = 0usize;
    let _ = tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            let _ = rx.changed().await;
            counter += 1;
        }
    })
    .await;

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert_eq!(counter, 0, "static reloader must never fire changed()");
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

    // Give the background task 300 ms to misbehave (spin-reload).
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
fn test_server_certs_keys_build_tls_acceptor(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::tls::ServerCertsKeys;

    let (cert, key) = generate_dummy_test_cert_der();
    let certs = vec![cert];

    let server_certs_keys = ServerCertsKeys { certs, key };
    let alpn = vec!["h2".to_string()];
    let options = TlsOptions::default();

    let result = server_certs_keys.build_tls_acceptor(&alpn, &options, &Default::default());
    assert!(result.is_err());
    Ok(())
}
