use crate::backend::health_check::HealthCheckSupervisor;
use crate::config::{
    load_from_path, Backend, BackendPoolConfig, Domain, DynamicConfig, RateLimitConfig,
    RouteRateLimitConfig, StaticConfig,
};
use crate::proxy::client_pool::ClientPool;
use crate::security::RateLimitManager;
use crate::telemetry::Metrics;
use crate::tls::DynamicCertResolver;
use arc_swap::ArcSwap;
use std::collections::{BTreeMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Handle;
use tracing::{debug, error, info};

/// Hot-swappable rate-limit manager; reused across reloads unless its config changes (see `try_reload`).
pub type SharedRateLimiter = Arc<ArcSwap<Option<Arc<RateLimitManager>>>>;

/// Hot-swappable HTTP client pool; reused unless backends/pool change (see `try_reload`).
pub type SharedClientPool = Arc<ArcSwap<ClientPool>>;

/// Hot-swappable dynamic configuration.
pub type SharedDynamicConfig = Arc<ArcSwap<DynamicConfig>>;

/// Apply a config change at runtime, atomically and without dropping connections.
///
/// Does:
/// - Re-parse + validate; on failure keeps the current config untouched (fail-safe).
/// - Atomically swap in the new dynamic config (routes, backends, headers, rate limits).
/// - Rebuild only what changed: rate-limiter (counters reset) and client pool (idle conns drained).
/// - Reconcile health checks and reload per-domain certs best-effort.
///
/// Does NOT:
/// - Touch live connections: each one keeps the config snapshot it took at accept time, so changes
///   apply to new connections only (no drain / GOAWAY).
/// - Apply static changes (listen, tls, fingerprint, timeout): logged, effective on restart only.
/// - Run concurrently: serialised by `reload_mutex`.
#[allow(clippy::too_many_arguments)]
pub async fn try_reload(
    config_path: &Path,
    static_cfg: &StaticConfig,
    dynamic_cfg: &SharedDynamicConfig,
    rate_limiter: &SharedRateLimiter,
    client_pool: &SharedClientPool,
    reload_mutex: &tokio::sync::Mutex<()>,
    metrics: &Arc<Metrics>,
    health_supervisor: &HealthCheckSupervisor,
    cert_resolver: Option<&Arc<DynamicCertResolver>>,
) {
    let _guard = reload_mutex.lock().await;

    info!(path = %config_path.display(), "Hot reload triggered");

    let new_config = match load_from_path(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Config reload failed: parse error, keeping current config");
            metrics.record_reload_error();
            return;
        }
    };

    // cross-reference validation
    if let Err(e) = new_config.validate_cross_refs() {
        error!(error = %e, "Config reload failed: validation error, keeping current config");
        metrics.record_reload_error();
        return;
    }

    let crate::config::ConfigParts { static_cfg: new_static, dynamic_cfg: new_dynamic } =
        new_config.into_parts();

    if new_static != *static_cfg {
        error!(
            "Config reload: static sections changed (listen, tls, fingerprint, timeout, …) \
             these changes have NO effect until restart"
        );
    }

    let old_dynamic = dynamic_cfg.load();

    audit_config_changes(&old_dynamic, &new_dynamic);

    // Rebuild (resetting counters) only when the rate-limit config or its `rate_limit_signature`
    // changes; unrelated edits (certs, headers, IP filters, backends) keep the existing buckets.
    if old_dynamic.security.rate_limit != new_dynamic.security.rate_limit
        || rate_limit_signature(&old_dynamic.domains) != rate_limit_signature(&new_dynamic.domains)
    {
        let candidate =
            RateLimitManager::new(&new_dynamic.security.rate_limit, &new_dynamic.domains);
        let new_mgr = if candidate.is_enabled() {
            Some(Arc::new(candidate))
        } else {
            None
        };
        rate_limiter.store(Arc::new(new_mgr));
        info!("Rate-limit config changed counters reset");
    }

    // Refresh the connection pool when backends are removed or pool config changes; in-flight
    // requests keep their old pool clone and only its idle connections are dropped afterwards.
    drain_removed_backends(
        &old_dynamic.backends,
        &new_dynamic.backends,
        &old_dynamic.backend_pool,
        &new_dynamic.backend_pool,
        client_pool,
        &static_cfg.timeout.keep_alive,
        static_cfg.timeout.upstream_connect_ms,
    );

    let hash = fnv1a_hash(&new_dynamic);
    let old_hash = fnv1a_hash(&old_dynamic);

    dynamic_cfg.store(Arc::new(new_dynamic));
    // Reconcile health-check tasks for added/removed backends.
    let fresh = dynamic_cfg.load();
    health_supervisor.reconcile(&fresh.backends, metrics, &Handle::current());

    // Reload certs per-domain, best-effort: a domain whose cert fails to load keeps its previous
    // cert instead of aborting the whole reload.
    let cert_report = match cert_resolver {
        Some(resolver) => {
            let report = resolver.update(&fresh.domains, metrics).await;
            if !resolver.has_serviceable_cert() && !fresh.domains.is_empty() {
                info!(
                    "TLS is configured but no certificate is serviceable after reload; all TLS \
                     handshakes will be rejected until a cert is provided"
                );
            }
            report
        }
        None => crate::tls::CertReloadReport::default(),
    };

    if cert_report.is_partial() {
        info!(
            failed = cert_report.failed,
            loaded = cert_report.loaded,
            "Some domain certificates failed to load on reload; new routes/backends are live and \
             failed domains keep their previous certificates"
        );
    }

    metrics.record_reload_success(hash);
    if hash == old_hash {
        debug!(
            config_hash = hash,
            "Config reloaded successfully (no effective dynamic changes)"
        );
    } else {
        debug!(
            config_hash = hash,
            old_config_hash = old_hash,
            "Config reloaded successfully, dynamic config changed"
        );
    }
}

fn audit_config_changes(old: &DynamicConfig, new: &DynamicConfig) {
    if old == new {
        info!("Config reload: no effective changes detected");
        return;
    }

    let old_addrs: HashSet<&str> = old.backends.iter().map(|b| b.address.as_str()).collect();
    let new_addrs: HashSet<&str> = new.backends.iter().map(|b| b.address.as_str()).collect();
    for addr in old_addrs.difference(&new_addrs) {
        info!(backend = addr, "Config diff: backend removed");
    }
    for addr in new_addrs.difference(&old_addrs) {
        info!(backend = addr, "Config diff: backend added");
    }

    let old_domains: HashSet<&str> = old.domains.iter().map(|d| d.label()).collect();
    let new_domains: HashSet<&str> = new.domains.iter().map(|d| d.label()).collect();
    for host in old_domains.difference(&new_domains) {
        info!(host = host, "Config diff: domain removed");
    }
    for host in new_domains.difference(&old_domains) {
        info!(host = host, "Config diff: domain added");
    }
    for domain in new.domains.iter() {
        if let Some(old_domain) = old.domains.iter().find(|d| d.host == domain.host) {
            if old_domain != domain {
                info!(host = domain.label(), "Config diff: domain changed");
                if old_domain.security != domain.security {
                    info!(
                        host = domain.label(),
                        "Config diff: domain security policy changed (ip_filter / rate_limit / headers)"
                    );
                }
            }
        }
    }

    if old.preserve_host != new.preserve_host {
        info!(
            old = old.preserve_host,
            new = new.preserve_host,
            "Config diff: preserve_host changed"
        );
    }

    if old.headers != new.headers {
        info!("Config diff: global header manipulation changed");
    }

    if old.security.headers != new.security.headers {
        info!("Config diff: security headers changed (HSTS / CSP / custom)");
    }
    if old.security.ip_filter != new.security.ip_filter {
        info!("Config diff: IP filter changed");
    }
    if old.security.rate_limit != new.security.rate_limit {
        info!("Config diff: rate-limit config changed");
    }
    if old.backend_pool != new.backend_pool {
        info!("Config diff: backend pool config changed, pool will be refreshed");
    }
}

/// The rate-limit-relevant projection of `domains`: per domain (keyed by label), its `rate_limit`
/// override plus the per-route overrides keyed by prefix. Equal signatures build an identical
/// manager, so its live counters survive reloads that only touch unrelated fields.
fn rate_limit_signature(
    domains: &[Domain],
) -> BTreeMap<&str, (Option<&RateLimitConfig>, BTreeMap<&str, &RouteRateLimitConfig>)> {
    domains
        .iter()
        .map(|domain| {
            let routes = domain
                .routes
                .iter()
                .filter_map(|route| {
                    route
                        .security
                        .as_ref()
                        .and_then(|s| s.rate_limit.as_ref())
                        .map(|rl| (route.prefix.as_str(), rl))
                })
                .collect();
            let domain_override = domain.security.as_ref().and_then(|s| s.rate_limit.as_ref());
            (domain.label(), (domain_override, routes))
        })
        .collect()
}

/// Replace the shared client pool when backends are removed or pool config changes; otherwise
/// keep it as-is to avoid resetting healthy connections.
fn drain_removed_backends(
    old_backends: &[Backend],
    new_backends: &[Backend],
    old_pool_cfg: &BackendPoolConfig,
    new_pool_cfg: &BackendPoolConfig,
    client_pool: &SharedClientPool,
    keep_alive: &crate::config::startup::timeout::KeepAliveConfig,
    upstream_connect_ms: Option<u64>,
) {
    let old_addrs: HashSet<&str> = old_backends.iter().map(|b| b.address.as_str()).collect();
    let new_addrs: HashSet<&str> = new_backends.iter().map(|b| b.address.as_str()).collect();

    let removed: Vec<&&str> = old_addrs.difference(&new_addrs).collect();
    let pool_cfg_changed = old_pool_cfg != new_pool_cfg;

    if removed.is_empty() && !pool_cfg_changed {
        return;
    }

    if !removed.is_empty() {
        info!(
            removed = ?removed,
            "Backends removed, refreshing connection pool to drain idle connections"
        );
    }
    if pool_cfg_changed {
        info!("Backend pool config changed, refreshing connection pool");
    }

    let new_pool = ClientPool::new(keep_alive, new_pool_cfg.clone(), upstream_connect_ms);
    client_pool.store(Arc::new(new_pool));
}

/// Fast hash of a `DynamicConfig` for the `huginn_config_hash` Prometheus gauge: only needs to be
/// stable within a process run and change whenever the config changes.
fn fnv1a_hash(dynamic: &DynamicConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    format!("{:?}", dynamic).hash(&mut hasher);
    hasher.finish()
}

pub fn initial_rate_limiter(dynamic: &DynamicConfig) -> SharedRateLimiter {
    let candidate = RateLimitManager::new(&dynamic.security.rate_limit, &dynamic.domains);
    let mgr = if candidate.is_enabled() {
        Some(Arc::new(candidate))
    } else {
        None
    };
    Arc::new(ArcSwap::new(Arc::new(mgr)))
}

pub fn initial_client_pool(
    static_cfg: &StaticConfig,
    pool_cfg: &BackendPoolConfig,
) -> SharedClientPool {
    let pool = ClientPool::new(
        &static_cfg.timeout.keep_alive,
        pool_cfg.clone(),
        static_cfg.timeout.upstream_connect_ms,
    );
    Arc::new(ArcSwap::from_pointee(pool))
}
