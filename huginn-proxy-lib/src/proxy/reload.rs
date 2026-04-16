use std::path::Path;
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use tracing::{error, info};

use crate::config::{load_from_path, DynamicConfig, StaticConfig};
use crate::security::RateLimitManager;

/// Shared, hot-swappable rate-limit manager.
///
/// Stored separately from `DynamicConfig` because it carries live counter state
/// that must survive reloads when the rate-limit configuration has not changed.
///
/// - On reload with **no rate-limit change** → old manager is reused as-is (counters preserved).
/// - On reload **with** rate-limit change → manager is rebuilt (counters reset).
pub type SharedRateLimiter = Arc<RwLock<Option<Arc<RateLimitManager>>>>;

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
    reload_mutex: &tokio::sync::Mutex<()>,
) {
    let _guard = reload_mutex.lock().await;

    info!(path = %config_path.display(), "Hot reload triggered");

    // re-parse
    let new_config = match load_from_path(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Config reload failed: parse error — keeping current config");
            return;
        }
    };

    // cross-reference validation
    if let Err(e) = new_config.validate_cross_refs() {
        error!(error = %e, "Config reload failed: validation error — keeping current config");
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

    // rebuild rate-limiter only when the config actually changed
    let old_dynamic = dynamic_cfg.load();
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

    // atomic swap
    dynamic_cfg.store(Arc::new(new_dynamic));
    info!("Config reloaded successfully");
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
