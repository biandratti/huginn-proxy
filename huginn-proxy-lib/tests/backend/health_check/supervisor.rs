use std::sync::Arc;
use std::time::Duration;

use huginn_proxy_lib::config::{Backend, HealthCheckConfig, HealthCheckType};
use huginn_proxy_lib::{HealthCheckSupervisor, HealthRegistry, Metrics};
use tokio::runtime::Handle;

#[tokio::test]
async fn supervisor_marks_unhealthy_on_unreachable_port() {
    let registry = Arc::new(HealthRegistry::new());
    let sup = HealthCheckSupervisor::new(registry.clone());
    let backend = Backend {
        address: "127.0.0.1:1".to_string(),
        http_version: None,
        health_check: Some(HealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            interval_secs: 1,
            timeout_secs: 1,
            unhealthy_threshold: 2,
            healthy_threshold: 1,
        }),
    };
    sup.reconcile(std::slice::from_ref(&backend), &Metrics::new_noop(), &Handle::current());
    // First tick is immediate, then one per second — allow time for 2 failed probes.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !registry.is_healthy("127.0.0.1:1"),
        "TCP connect should fail and the counter should flip upstream to unhealthy"
    );
    sup.shutdown();
}
