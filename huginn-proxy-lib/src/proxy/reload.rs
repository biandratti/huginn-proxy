use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use tracing::{error, info};

use crate::config::{load_from_path, Backend, BackendPoolConfig, DynamicConfig, StaticConfig};
use crate::proxy::client_pool::ClientPool;
use crate::security::RateLimitManager;
use crate::telemetry::Metrics;

/// Shared, hot-swappable rate-limit manager.
///
/// Stored separately from `DynamicConfig` because it carries live counter state
/// that must survive reloads when the rate-limit configuration has not changed.
///
/// - On reload with **no rate-limit change** → old manager is reused as-is (counters preserved).
/// - On reload **with** rate-limit change → manager is rebuilt (counters reset).
pub type SharedRateLimiter = Arc<RwLock<Option<Arc<RateLimitManager>>>>;

/// Shared, hot-swappable HTTP client pool.
///
/// When backends are removed from the config the old pool is replaced atomically.
/// In-flight requests hold an `Arc<ClientPool>` clone and complete normally; once
/// they finish, the old pool is dropped and its idle connections are closed.
/// New backends are served on-demand by the fresh pool.
pub type SharedClientPool = Arc<ArcSwap<ClientPool>>;

/// Attempt a hot config reload.
///
/// Re-parses the TOML, validates cross-references, warns on static-section changes,
/// and atomically swaps in the new `DynamicConfig`. If parsing or validation fails
/// the current config is kept untouched. Serialised via `reload_mutex` so concurrent
/// SIGHUP / watcher events queue rather than running in parallel.
pub async fn try_reload(
    config_path: &Path,
    static_cfg: &StaticConfig,
    dynamic_cfg: &Arc<ArcSwap<DynamicConfig>>,
    rate_limiter: &SharedRateLimiter,
    client_pool: &SharedClientPool,
    reload_mutex: &tokio::sync::Mutex<()>,
    metrics: &Arc<Metrics>,
) {
    let _guard = reload_mutex.lock().await;

    info!(path = %config_path.display(), "Hot reload triggered");

    // re-parse
    let new_config = match load_from_path(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Config reload failed: parse error — keeping current config");
            metrics.record_reload_error();
            return;
        }
    };

    // cross-reference validation
    if let Err(e) = new_config.validate_cross_refs() {
        error!(error = %e, "Config reload failed: validation error — keeping current config");
        metrics.record_reload_error();
        return;
    }

    let (new_static, new_dynamic) = new_config.into_parts();

    // Warn on static section changes (ignored — restart required)
    if new_static != *static_cfg {
        error!(
            "Config reload: static sections changed (listen, tls, fingerprint, timeout, …) \
             — these changes have NO effect until restart"
        );
    }

    let old_dynamic = dynamic_cfg.load();

    audit_config_changes(&old_dynamic, &new_dynamic);

    // rebuild rate-limiter only when the config actually changed
    if old_dynamic.security.rate_limit != new_dynamic.security.rate_limit {
        let new_mgr = if new_dynamic.security.rate_limit.enabled {
            Some(Arc::new(RateLimitManager::new(
                &new_dynamic.security.rate_limit,
                &new_dynamic.routes,
            )))
        } else {
            None
        };
        *rate_limiter.write().unwrap_or_else(|e| e.into_inner()) = new_mgr;
        info!("Rate-limit config changed — counters reset");
    }

    // Drain removed backends: replace the client pool so no new requests reuse
    // connections to backends that are no longer in the config.
    // In-flight handlers hold their own Arc<ClientPool> clone and finish normally;
    // once they complete the old pool is dropped and its idle connections are closed.
    drain_removed_backends(&old_dynamic.backends, &new_dynamic.backends, client_pool, static_cfg);

    let hash = fnv1a_hash(&new_dynamic);

    dynamic_cfg.store(Arc::new(new_dynamic));

    metrics.record_reload_success(hash);
    info!(config_hash = hash, "Config reloaded successfully");
}

/// Audit and log what changed between two `DynamicConfig` snapshots.
fn audit_config_changes(old: &DynamicConfig, new: &DynamicConfig) {
    if old == new {
        info!("Config reload: no effective changes detected");
        return;
    }

    // Backends
    let old_addrs: HashSet<&str> = old.backends.iter().map(|b| b.address.as_str()).collect();
    let new_addrs: HashSet<&str> = new.backends.iter().map(|b| b.address.as_str()).collect();
    for addr in old_addrs.difference(&new_addrs) {
        info!(backend = addr, "Config diff: backend removed");
    }
    for addr in new_addrs.difference(&old_addrs) {
        info!(backend = addr, "Config diff: backend added");
    }

    // Routes
    let old_routes: HashSet<&str> = old.routes.iter().map(|r| r.prefix.as_str()).collect();
    let new_routes: HashSet<&str> = new.routes.iter().map(|r| r.prefix.as_str()).collect();
    for prefix in old_routes.difference(&new_routes) {
        info!(prefix = prefix, "Config diff: route removed");
    }
    for prefix in new_routes.difference(&old_routes) {
        info!(prefix = prefix, "Config diff: route added");
    }
    for route in &new.routes {
        if let Some(old_route) = old.routes.iter().find(|r| r.prefix == route.prefix) {
            if old_route != route {
                info!(prefix = route.prefix, "Config diff: route changed");
            }
        }
    }

    // preserve_host
    if old.preserve_host != new.preserve_host {
        info!(
            old = old.preserve_host,
            new = new.preserve_host,
            "Config diff: preserve_host changed"
        );
    }

    // Global headers
    if old.headers != new.headers {
        info!("Config diff: global header manipulation changed");
    }

    // Security
    if old.security.headers != new.security.headers {
        info!("Config diff: security headers changed (HSTS / CSP / custom)");
    }
    if old.security.ip_filter != new.security.ip_filter {
        info!("Config diff: IP filter changed");
    }
    if old.security.rate_limit != new.security.rate_limit {
        info!("Config diff: rate-limit config changed");
    }
}

/// Replace the shared client pool when backends have been removed.
///
/// If the set of backend addresses is unchanged the existing pool is kept as-is
/// (avoids needlessly resetting healthy connections).
fn drain_removed_backends(
    old_backends: &[Backend],
    new_backends: &[Backend],
    client_pool: &SharedClientPool,
    static_cfg: &StaticConfig,
) {
    let old_addrs: HashSet<&str> = old_backends.iter().map(|b| b.address.as_str()).collect();
    let new_addrs: HashSet<&str> = new_backends.iter().map(|b| b.address.as_str()).collect();

    let removed: Vec<&&str> = old_addrs.difference(&new_addrs).collect();
    if removed.is_empty() {
        return;
    }

    info!(
        removed = ?removed,
        "Backends removed — refreshing connection pool to drain idle connections"
    );
    let new_pool = ClientPool::new(&static_cfg.timeout.keep_alive, BackendPoolConfig::default());
    client_pool.store(Arc::new(new_pool));
}

/// Compute a fast FNV-1a hash of a `DynamicConfig` via its `Debug` representation.
///
/// Used exclusively for the `huginn_config_hash` Prometheus gauge — must be
/// deterministic within a process run and change whenever the config changes.
/// Cross-run or cross-version stability is not required.
fn fnv1a_hash(dynamic: &DynamicConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    format!("{:?}", dynamic).hash(&mut hasher);
    hasher.finish()
}

/// Build the initial `SharedRateLimiter` from the starting `DynamicConfig`.
pub fn initial_rate_limiter(dynamic: &DynamicConfig) -> SharedRateLimiter {
    let mgr = if dynamic.security.rate_limit.enabled {
        Some(Arc::new(RateLimitManager::new(&dynamic.security.rate_limit, &dynamic.routes)))
    } else {
        None
    };
    Arc::new(RwLock::new(mgr))
}

/// Build the initial `SharedClientPool`.
pub fn initial_client_pool(static_cfg: &StaticConfig) -> SharedClientPool {
    let pool = ClientPool::new(&static_cfg.timeout.keep_alive, BackendPoolConfig::default());
    Arc::new(ArcSwap::from_pointee(pool))
}
