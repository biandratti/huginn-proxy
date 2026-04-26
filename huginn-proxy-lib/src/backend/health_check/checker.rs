//! Spawns and reconciles per-upstream health checker tasks.
//!
//! Mirrors the structure of `rust-rpxy`’s `spawn_health_checkers` / `run_health_checker`, adapted
//! to huginn’s flat `backends` list: one background task per `Backend` with an enabled health check
//! (TCP or HTTP `GET` over plain `http://`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::{Backend, HealthCheckConfig, HealthCheckType};
use crate::telemetry::Metrics;

use super::check_http::check_http;
use super::check_http::HealthCheckHttpClient;
use super::check_tcp::check_tcp;
use super::counter::ConsecutiveCounter;
use super::health::UpstreamHealth;
use super::HealthRegistry;

struct ActiveChecker {
    config: HealthCheckConfig,
    cancel: CancellationToken,
    _join: JoinHandle<()>,
}

/// Owns the Tokio tasks that probe upstreams and update [`super::HealthRegistry`].
pub struct HealthCheckSupervisor {
    registry: Arc<HealthRegistry>,
    active: Mutex<HashMap<String, ActiveChecker>>,
}

impl HealthCheckSupervisor {
    pub fn new(registry: Arc<HealthRegistry>) -> Self {
        Self { registry, active: Mutex::new(HashMap::new()) }
    }

    /// Stops all checker tasks (used on graceful process shutdown).
    pub fn shutdown(&self) {
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        for (addr, ac) in guard.drain() {
            ac.cancel.cancel();
            info!(backend = %addr, "health check task cancelled (shutdown)");
        }
    }

    /// Diff `backends` against the running set: cancels removed/changed, spawns new tasks.
    pub fn reconcile(&self, backends: &[Backend], metrics: &Arc<Metrics>, handle: &Handle) {
        let wanted = collect_wanted_checks(backends);

        {
            let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
            let to_remove: Vec<String> = guard
                .keys()
                .filter(|k| !wanted.contains_key(*k))
                .cloned()
                .collect();
            for addr in to_remove {
                if let Some(ac) = guard.remove(&addr) {
                    ac.cancel.cancel();
                    self.registry.remove(&addr);
                    info!(backend = %addr, "health check removed (config)");
                }
            }
        }

        for (addr, config) in wanted {
            let need_new = {
                let guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
                match guard.get(&addr) {
                    None => true,
                    Some(c) if c.config != config => true,
                    _ => false,
                }
            };
            if !need_new {
                continue;
            }

            if let Some(old) = self
                .active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&addr)
            {
                old.cancel.cancel();
            }

            let health = self.registry.get_or_create(&addr);
            let cancel = CancellationToken::new();
            let m = metrics.clone();
            let addr_for_task = addr.clone();
            let task_token = cancel.clone();
            let join = handle.spawn(run_health_checker(
                addr_for_task,
                health,
                config.clone(),
                task_token,
                m,
            ));

            let ac = ActiveChecker { config, cancel, _join: join };
            self.active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(addr, ac);
        }
    }
}

fn collect_wanted_checks(backends: &[Backend]) -> HashMap<String, HealthCheckConfig> {
    let mut out = HashMap::new();
    for b in backends {
        let Some(hc) = b.health_check.clone() else {
            continue;
        };
        out.insert(b.address.clone(), hc);
    }
    out
}

/// Public for integration tests; production uses [`HealthCheckSupervisor`].
pub async fn run_health_checker(
    address: String,
    health: Arc<UpstreamHealth>,
    config: HealthCheckConfig,
    cancel: CancellationToken,
    metrics: Arc<Metrics>,
) {
    let mut counter = ConsecutiveCounter::new(config.unhealthy_threshold, config.healthy_threshold);
    let timeout = Duration::from_secs(config.timeout_secs);
    let http_client = if matches!(&config.check_type, HealthCheckType::Http { .. }) {
        Some(HealthCheckHttpClient::new(config.timeout_secs))
    } else {
        None
    };
    let mut ticker = interval(Duration::from_secs(config.interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // First `tick` completes immediately — same effect as an immediate first probe in rpxy.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!(backend = %address, "health check loop stopped");
                return;
            }
            _ = ticker.tick() => {
                run_one_probe(
                    &address,
                    &health,
                    &config,
                    http_client.as_ref(),
                    &mut counter,
                    timeout,
                    &metrics,
                )
                .await;
            }
        }
    }
}

async fn run_one_probe(
    address: &str,
    health: &Arc<UpstreamHealth>,
    config: &HealthCheckConfig,
    http_client: Option<&HealthCheckHttpClient>,
    counter: &mut ConsecutiveCounter,
    timeout: Duration,
    metrics: &Metrics,
) {
    let ok = match &config.check_type {
        HealthCheckType::Tcp => check_tcp(address, timeout).await,
        HealthCheckType::Http { path, expected_status } => {
            let Some(client) = http_client else {
                return;
            };
            check_http(client, address, path, *expected_status, timeout).await
        }
    };
    metrics.record_health_check_probe(address, ok);
    if let Some(new_state) = counter.record(ok) {
        health.set(new_state);
        if new_state {
            info!(backend = %address, "upstream is now healthy (enough consecutive successes)");
        } else {
            info!(backend = %address, "upstream is now unhealthy (enough consecutive failures)");
        }
    }
}
