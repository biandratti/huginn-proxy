use std::time::Duration;

use serial_test::serial;

use super::helpers::{
    free_port, http_get, send_sighup, spawn_mock_backend, spawn_proxy, toml_single_backend,
    toml_with_routes, wait_for_backend, write_toml,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn watch_triggers_reload_on_toml_change() -> TestResult {
    let (backend_a, _bh_a) = spawn_mock_backend("a").await?;
    let (backend_b, _bh_b) = spawn_mock_backend("b").await?;

    let listen_port = free_port()?;
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;

    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_a))?;

    let (proxy_addr, _ph) = spawn_proxy(tmp.path(), true, 1).await?;

    let (status, backend) = http_get(proxy_addr, "/").await?;
    assert_eq!(status, 200, "expected 200 from backend A");
    assert_eq!(backend.as_deref(), Some("a"), "expected x-backend: a");

    // Switch config to backend B.
    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_b))?;

    // Wait for debounce (1 s) + reload + retry window (up to 15 s total).
    wait_for_backend(proxy_addr, "/", "b", 15).await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn sighup_triggers_reload() -> TestResult {
    let (backend_a, _bh_a) = spawn_mock_backend("a").await?;
    let (backend_b, _bh_b) = spawn_mock_backend("b").await?;

    let listen_port = free_port()?;
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;

    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_a))?;

    let (proxy_addr, _ph) = spawn_proxy(tmp.path(), false, 60).await?;

    let (status, backend) = http_get(proxy_addr, "/").await?;
    assert_eq!(status, 200);
    assert_eq!(backend.as_deref(), Some("a"));

    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_b))?;

    // Allow the proxy task a moment to ensure its SIGHUP handler is registered.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let signal_delivered = send_sighup();
    if !signal_delivered {
        // Some CI/sandbox environments block self-signalling. Skip gracefully.
        return Ok(());
    }

    wait_for_backend(proxy_addr, "/", "b", 10).await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn new_route_is_accessible_after_reload() -> TestResult {
    let (backend_a, _bh_a) = spawn_mock_backend("a").await?;
    let (backend_b, _bh_b) = spawn_mock_backend("b").await?;

    let listen_port = free_port()?;
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;

    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_a))?;

    let (proxy_addr, _ph) = spawn_proxy(tmp.path(), false, 60).await?;

    // Before reload: "/api" falls through to "/" → backend A.
    let (status, backend) = http_get(proxy_addr, "/api/health").await?;
    assert_eq!(status, 200);
    assert_eq!(backend.as_deref(), Some("a"), "/api/health should reach A before reload");

    // Updated config: add /api route → B; keep "/" → A.
    write_toml(
        tmp.path(),
        &toml_with_routes(
            listen_port,
            &[backend_a, backend_b],
            &[("/api", backend_b), ("/", backend_a)],
        ),
    )?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let signal_delivered = send_sighup();
    if !signal_delivered {
        return Ok(());
    }

    // After reload: "/api/health" should now reach backend B.
    wait_for_backend(proxy_addr, "/api/health", "b", 10).await?;

    // "/" should still reach backend A.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, backend) = http_get(proxy_addr, "/").await?;
    assert_eq!(status, 200);
    assert_eq!(backend.as_deref(), Some("a"), "/ should still reach A");

    Ok(())
}
