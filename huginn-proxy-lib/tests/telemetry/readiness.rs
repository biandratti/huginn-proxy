use huginn_proxy_lib::{NotReadyReason, Readiness};

#[test]
fn starts_not_ready_as_starting() {
    let r = Readiness::new();
    assert!(!r.is_ready());
    assert_eq!(r.not_ready_reason(), Some(NotReadyReason::ProxyStarting));
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
    assert_eq!(r.not_ready_reason(), Some(NotReadyReason::ProxyDraining));
}

#[test]
fn mark_ready_cannot_cancel_draining() {
    let r = Readiness::new();
    r.mark_draining();
    r.mark_ready();
    assert!(!r.is_ready());
    assert_eq!(r.not_ready_reason(), Some(NotReadyReason::ProxyDraining));
}

#[test]
fn draining_before_listeners_are_up_reports_draining() {
    let r = Readiness::new();
    r.mark_draining();
    assert_eq!(r.not_ready_reason(), Some(NotReadyReason::ProxyDraining));
}
