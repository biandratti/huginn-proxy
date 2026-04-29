use std::sync::Arc;
use std::time::Duration;

use huginn_proxy_lib::config::{Backend, HealthCheckConfig, HealthCheckType};
use huginn_proxy_lib::{HealthCheckSupervisor, HealthRegistry, Metrics};
use tokio::runtime::Handle;

fn tcp_backend(addr: &str, interval: u64, threshold: u32) -> Backend {
    Backend {
        address: addr.to_string(),
        http_version: None,
        health_check: Some(HealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            interval_secs: interval,
            timeout_secs: 1,
            unhealthy_threshold: threshold,
            healthy_threshold: 1,
        }),
    }
}

#[tokio::test]
async fn supervisor_marks_unhealthy_on_unreachable_port() {
    let registry = Arc::new(HealthRegistry::new());
    let sup = HealthCheckSupervisor::new(registry.clone());
    let backend = tcp_backend("127.0.0.1:1", 1, 2);
    sup.reconcile(std::slice::from_ref(&backend), &Metrics::new_noop(), &Handle::current());
    // First tick is immediate, then one per second — allow time for 2 failed probes.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !registry.is_healthy("127.0.0.1:1"),
        "TCP connect should fail and the counter should flip upstream to unhealthy"
    );
    sup.shutdown();
}

#[tokio::test]
async fn supervisor_removes_backend_on_reconcile() {
    let registry = Arc::new(HealthRegistry::new());
    let sup = HealthCheckSupervisor::new(registry.clone());

    let backend = tcp_backend("127.0.0.1:1", 1, 1);
    sup.reconcile(std::slice::from_ref(&backend), &Metrics::new_noop(), &Handle::current());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!registry.is_healthy("127.0.0.1:1"), "should be unhealthy before removal");

    sup.reconcile(&[], &Metrics::new_noop(), &Handle::current());

    assert!(
        registry.is_healthy("127.0.0.1:1"),
        "after removal opt-in fallback should return healthy for unknown address"
    );
    assert_eq!(registry.len(), 0, "registry should be empty after removal");
    sup.shutdown();
}

#[tokio::test]
async fn supervisor_adds_backend_on_reconcile() {
    let registry = Arc::new(HealthRegistry::new());
    let sup = HealthCheckSupervisor::new(registry.clone());

    // Start with no backends.
    sup.reconcile(&[], &Metrics::new_noop(), &Handle::current());
    assert_eq!(registry.len(), 0);

    // Add the backend.
    let backend = tcp_backend("127.0.0.1:1", 1, 2);
    sup.reconcile(std::slice::from_ref(&backend), &Metrics::new_noop(), &Handle::current());
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        !registry.is_healthy("127.0.0.1:1"),
        "task should have been spawned and driven backend to unhealthy"
    );
    sup.shutdown();
}

#[tokio::test]
async fn supervisor_restarts_task_on_config_change() {
    let registry = Arc::new(HealthRegistry::new());
    let sup = HealthCheckSupervisor::new(registry.clone());

    let slow = tcp_backend("127.0.0.1:1", 5, 10);
    sup.reconcile(std::slice::from_ref(&slow), &Metrics::new_noop(), &Handle::current());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        registry.is_healthy("127.0.0.1:1"),
        "should still be healthy with high threshold"
    );

    let fast = tcp_backend("127.0.0.1:1", 1, 1);
    sup.reconcile(std::slice::from_ref(&fast), &Metrics::new_noop(), &Handle::current());
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        !registry.is_healthy("127.0.0.1:1"),
        "new task with fast threshold should have marked backend unhealthy"
    );
    sup.shutdown();
}
