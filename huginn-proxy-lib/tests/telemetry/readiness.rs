use huginn_proxy_lib::Readiness;

#[test]
fn starts_not_ready_as_starting() {
    let r = Readiness::new();
    assert!(!r.is_ready());
    assert_eq!(r.not_ready_reason(), Some("proxy_starting"));
}

#[test]
fn mark_ready_clears_reason() {
    let r = Readiness::new();
    r.mark_ready();
    assert!(r.is_ready());
    assert_eq!(r.not_ready_reason(), None);
}

#[test]
fn mark_draining_uses_drain_reason() {
    let r = Readiness::new();
    r.mark_ready();
    r.mark_draining();
    assert!(!r.is_ready());
    assert_eq!(r.not_ready_reason(), Some("proxy_draining"));
}
