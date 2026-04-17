use std::io::Write as _;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tempfile::NamedTempFile;

use huginn_proxy_lib::{
    initial_client_pool, initial_rate_limiter, try_reload, Config, DynamicConfig, Metrics,
    SharedClientPool, SharedRateLimiter, StaticConfig,
};

use super::helpers::{
    free_port, spawn_mock_backend, toml_single_backend, toml_with_rate_limit, toml_with_routes,
    write_toml,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn minimal_config(backend_addr: std::net::SocketAddr, listen_port: u16) -> Config {
    use huginn_proxy_lib::config::{
        Backend, FingerprintConfig, KeepAliveConfig, ListenConfig, LoggingConfig, Route,
        SecurityConfig, TelemetryConfig, TimeoutConfig,
    };

    Config {
        listen: ListenConfig {
            addrs: vec![format!("127.0.0.1:{listen_port}")
                .parse()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 0)))],
            ..Default::default()
        },
        backends: vec![Backend { address: backend_addr.to_string(), http_version: None }],
        routes: vec![Route {
            prefix: "/".to_string(),
            backend: backend_addr.to_string(),
            fingerprinting: false,
            force_new_connection: false,
            replace_path: None,
            rate_limit: None,
            headers: None,
        }],
        tls: None,
        fingerprint: FingerprintConfig {
            tls_enabled: false,
            http_enabled: false,
            tcp_enabled: false,
            max_capture: 0,
        },
        logging: LoggingConfig { level: "warn".to_string(), show_target: false },
        timeout: TimeoutConfig {
            connect_ms: 1000,
            idle_ms: 5000,
            shutdown_secs: 1,
            tls_handshake_secs: 5,
            connection_handling_secs: 10,
            keep_alive: KeepAliveConfig::default(),
        },
        security: SecurityConfig::default(),
        telemetry: TelemetryConfig { metrics_port: None, otel_log_level: "warn".to_string() },
        headers: None,
        preserve_host: false,
    }
}

fn into_shared(
    config: Config,
) -> (
    Arc<StaticConfig>,
    Arc<ArcSwap<DynamicConfig>>,
    SharedRateLimiter,
    SharedClientPool,
) {
    let (static_cfg, dynamic_cfg) = config.into_parts();
    let static_cfg = Arc::new(static_cfg);
    let shared_dyn = Arc::new(ArcSwap::from_pointee(dynamic_cfg));
    let rate_limiter = initial_rate_limiter(&shared_dyn.load());
    let client_pool = initial_client_pool(&static_cfg);
    (static_cfg, shared_dyn, rate_limiter, client_pool)
}

#[tokio::test]
async fn reload_invalid_toml_keeps_current_config() -> TestResult {
    let (backend_addr, _bh) = spawn_mock_backend("a").await?;
    let listen_port = free_port()?;
    let config = minimal_config(backend_addr, listen_port);
    let (static_cfg, shared_dyn, rate_limiter, client_pool) = into_shared(config);

    let before = (*shared_dyn.load_full()).clone();

    let tmp = NamedTempFile::new()?;
    write!(tmp.as_file(), "this is not valid toml !!!! @@@")?;

    let reload_mutex = tokio::sync::Mutex::new(());
    let metrics = Metrics::new_noop();

    try_reload(
        tmp.path(),
        &static_cfg,
        &shared_dyn,
        &rate_limiter,
        &client_pool,
        &reload_mutex,
        &metrics,
    )
    .await;

    let after = (*shared_dyn.load_full()).clone();
    assert_eq!(before, after, "DynamicConfig must not change after a parse failure");
    Ok(())
}

#[tokio::test]
async fn drain_removed_backend_replaces_pool() -> TestResult {
    let (backend_a, _bh_a) = spawn_mock_backend("a").await?;
    let (backend_b, _bh_b) = spawn_mock_backend("b").await?;

    let listen_port = free_port()?;

    let initial_toml_file = NamedTempFile::new()?;
    write_toml(
        initial_toml_file.path(),
        &toml_with_routes(
            listen_port,
            &[backend_a, backend_b],
            &[("/", backend_a), ("/b", backend_b)],
        ),
    )?;

    let config = huginn_proxy_lib::config::load_from_path(initial_toml_file.path())?;
    let (static_cfg, shared_dyn, rate_limiter, client_pool) = into_shared(config);

    let ptr_before = Arc::as_ptr(&client_pool.load_full());

    // New config: backend B removed, only "/" → A remains.
    write_toml(initial_toml_file.path(), &toml_single_backend(listen_port, backend_a))?;

    let reload_mutex = tokio::sync::Mutex::new(());
    let metrics = Metrics::new_noop();

    try_reload(
        initial_toml_file.path(),
        &static_cfg,
        &shared_dyn,
        &rate_limiter,
        &client_pool,
        &reload_mutex,
        &metrics,
    )
    .await;

    let ptr_after = Arc::as_ptr(&client_pool.load_full());

    assert_ne!(ptr_before, ptr_after, "ClientPool must be replaced when backends are removed");

    let new_dyn = shared_dyn.load_full();
    assert_eq!(new_dyn.backends.len(), 1);
    assert_eq!(new_dyn.backends[0].address, backend_a.to_string());
    Ok(())
}

#[tokio::test]
async fn reload_static_change_proceeds_without_crash() -> TestResult {
    let (backend_a, _bh) = spawn_mock_backend("a").await?;

    let listen_port = free_port()?;
    let different_listen_port = free_port()?;

    let tmp = NamedTempFile::new()?;
    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_a))?;

    let config = huginn_proxy_lib::config::load_from_path(tmp.path())?;
    let (static_cfg, shared_dyn, rate_limiter, client_pool) = into_shared(config);

    let dynamic_before = (*shared_dyn.load_full()).clone();

    // Change only the listen address (static section); keep dynamic config identical.
    write_toml(tmp.path(), &toml_single_backend(different_listen_port, backend_a))?;

    let reload_mutex = tokio::sync::Mutex::new(());
    let metrics = Metrics::new_noop();

    // Must not panic; the static change is logged as an error but otherwise ignored.
    try_reload(
        tmp.path(),
        &static_cfg,
        &shared_dyn,
        &rate_limiter,
        &client_pool,
        &reload_mutex,
        &metrics,
    )
    .await;

    let dynamic_after = (*shared_dyn.load_full()).clone();
    assert_eq!(
        dynamic_before, dynamic_after,
        "DynamicConfig must be unchanged when only static fields differ"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_reloads_are_serialized() -> TestResult {
    let (backend_addr, _bh) = spawn_mock_backend("a").await?;

    let listen_port = free_port()?;
    let tmp = NamedTempFile::new()?;
    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_addr))?;

    let config = huginn_proxy_lib::config::load_from_path(tmp.path())?;
    let (static_cfg, shared_dyn, rate_limiter, client_pool) = into_shared(config);

    let reload_mutex = Arc::new(tokio::sync::Mutex::new(()));
    let metrics = Metrics::new_noop();

    let config_path = tmp.path().to_path_buf();
    let mut tasks = Vec::new();

    for _ in 0..5 {
        let config_path = config_path.clone();
        let static_cfg = Arc::clone(&static_cfg);
        let shared_dyn = Arc::clone(&shared_dyn);
        let rate_limiter = Arc::clone(&rate_limiter);
        let client_pool = Arc::clone(&client_pool);
        let reload_mutex = Arc::clone(&reload_mutex);
        let metrics = Arc::clone(&metrics);

        tasks.push(tokio::spawn(async move {
            try_reload(
                &config_path,
                &static_cfg,
                &shared_dyn,
                &rate_limiter,
                &client_pool,
                &reload_mutex,
                &metrics,
            )
            .await;
        }));
    }

    for task in tasks {
        task.await?;
    }

    let dyn_cfg = shared_dyn.load_full();
    assert_eq!(dyn_cfg.backends.len(), 1);
    assert_eq!(dyn_cfg.backends[0].address, backend_addr.to_string());
    Ok(())
}

#[tokio::test]
async fn reload_toggles_rate_limiter() -> TestResult {
    let (backend_addr, _bh) = spawn_mock_backend("a").await?;

    let listen_port = free_port()?;
    let tmp = NamedTempFile::new()?;

    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_addr))?;

    let config = huginn_proxy_lib::config::load_from_path(tmp.path())?;
    let (static_cfg, shared_dyn, rate_limiter, client_pool) = into_shared(config);

    {
        let guard = rate_limiter.read().unwrap_or_else(|e| e.into_inner());
        assert!(guard.is_none(), "rate limiter should start as None");
    }

    let reload_mutex = tokio::sync::Mutex::new(());
    let metrics = Metrics::new_noop();

    // Reload with rate limiting ENABLED.
    write_toml(tmp.path(), &toml_with_rate_limit(listen_port, backend_addr))?;
    try_reload(
        tmp.path(),
        &static_cfg,
        &shared_dyn,
        &rate_limiter,
        &client_pool,
        &reload_mutex,
        &metrics,
    )
    .await;

    {
        let guard = rate_limiter.read().unwrap_or_else(|e| e.into_inner());
        assert!(guard.is_some(), "rate limiter should be Some after enabling it");
    }

    // Reload with rate limiting DISABLED again.
    write_toml(tmp.path(), &toml_single_backend(listen_port, backend_addr))?;
    try_reload(
        tmp.path(),
        &static_cfg,
        &shared_dyn,
        &rate_limiter,
        &client_pool,
        &reload_mutex,
        &metrics,
    )
    .await;

    {
        let guard = rate_limiter.read().unwrap_or_else(|e| e.into_inner());
        assert!(guard.is_none(), "rate limiter should be None after disabling it");
    }

    Ok(())
}
