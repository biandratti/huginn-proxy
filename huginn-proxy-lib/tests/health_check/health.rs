use huginn_proxy_lib::BackendHealth;

#[test]
fn initial_state_is_healthy() {
    let h = BackendHealth::new();
    assert!(h.is_healthy());
}

#[test]
fn default_is_healthy() {
    let h = BackendHealth::default();
    assert!(h.is_healthy());
}

#[test]
fn set_unhealthy_and_recover() {
    let h = BackendHealth::new();
    h.set(false);
    assert!(!h.is_healthy());
    h.set(true);
    assert!(h.is_healthy());
}

#[test]
fn idempotent_set() {
    let h = BackendHealth::new();
    h.set(true);
    h.set(true);
    assert!(h.is_healthy());
    h.set(false);
    h.set(false);
    assert!(!h.is_healthy());
}
