use http::Version;
use huginn_proxy_lib::config::{BackendPoolConfig, KeepAliveConfig};
use huginn_proxy_lib::proxy::ClientPool;

fn default_keep_alive_config() -> KeepAliveConfig {
    KeepAliveConfig { enabled: true, timeout_secs: 90 }
}

#[test]
fn test_client_pool_creation() {
    let config = default_keep_alive_config();
    let pool_config = BackendPoolConfig::default();
    let _pool = ClientPool::new(&config, pool_config);
}

#[test]
fn test_get_client_http11_pooled() {
    let config = default_keep_alive_config();
    let pool_config = BackendPoolConfig::default();
    let pool = ClientPool::new(&config, pool_config);

    let client = pool.get_client(Version::HTTP_11, false);
    assert!(client.is_some(), "HTTP/1.1 pooled client should be returned");
}

#[test]
fn test_get_client_http2_pooled() {
    let config = default_keep_alive_config();
    let pool_config = BackendPoolConfig::default();
    let pool = ClientPool::new(&config, pool_config);

    let client = pool.get_client(Version::HTTP_2, false);
    assert!(client.is_some(), "HTTP/2 pooled client should be returned");
}

#[test]
fn test_get_client_http09_defaults_to_http11() {
    let config = default_keep_alive_config();
    let pool_config = BackendPoolConfig::default();
    let pool = ClientPool::new(&config, pool_config);

    let client = pool.get_client(Version::HTTP_09, false);
    assert!(client.is_some(), "HTTP/0.9 should fallback to HTTP/1.1 client");
}

#[test]
fn test_get_client_force_new_returns_none() {
    let config = default_keep_alive_config();
    let pool_config = BackendPoolConfig::default();
    let pool = ClientPool::new(&config, pool_config);

    let client_http11 = pool.get_client(Version::HTTP_11, true);
    let client_http2 = pool.get_client(Version::HTTP_2, true);

    assert!(client_http11.is_none(), "force_new should return None for HTTP/1.1");
    assert!(client_http2.is_none(), "force_new should return None for HTTP/2");
}

#[test]
fn test_create_oneoff_client() {
    let config = default_keep_alive_config();
    let pool_config = BackendPoolConfig::default();
    let pool = ClientPool::new(&config, pool_config);

    let _oneoff_http11 = pool.create_oneoff_client(Version::HTTP_11);
    let _oneoff_http2 = pool.create_oneoff_client(Version::HTTP_2);
}

#[test]
fn test_pool_config_default() {
    let config = BackendPoolConfig::default();
    assert!(config.enabled, "Pool should be enabled by default");
    assert_eq!(config.idle_timeout, 90, "Default idle timeout should be 90 seconds");
    assert_eq!(
        config.pool_max_idle_per_host, 0,
        "Default max idle per host should be 0 (unlimited)"
    );
}

#[test]
fn test_client_pool_clone() {
    let config = default_keep_alive_config();
    let pool_config = BackendPoolConfig::default();
    let pool = ClientPool::new(&config, pool_config);

    let pool_clone = pool.clone();

    // Verify both pools work correctly
    assert!(pool.get_client(Version::HTTP_11, false).is_some());
    assert!(pool_clone.get_client(Version::HTTP_11, false).is_some());
}

#[test]
fn test_keep_alive_disabled() {
    let config = KeepAliveConfig { enabled: false, timeout_secs: 0 };
    let pool_config = BackendPoolConfig::default();
    let pool = ClientPool::new(&config, pool_config);

    // Pool should still be created, but without keep-alive
    assert!(pool.get_client(Version::HTTP_11, false).is_some());
}
