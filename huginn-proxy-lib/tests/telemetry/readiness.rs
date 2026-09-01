use huginn_proxy_lib::{GateState, NotReadyReason, Readiness};
use std::sync::Arc;

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

#[test]
fn gate_absent_after_mark_ready() {
    let r = Readiness::new();
    r.set_gate(Arc::new(|| GateState::Absent));
    r.mark_ready();
    assert_eq!(r.not_ready_reason(), Some(NotReadyReason::CaptureAbsent));
    assert_eq!(NotReadyReason::CaptureAbsent.text_token(), "NOCAPTURE");
}

#[test]
fn proxy_draining_outranks_gate() {
    let r = Readiness::new();
    r.set_gate(Arc::new(|| GateState::Detached));
    r.mark_ready();
    r.mark_draining();
    assert_eq!(r.not_ready_reason(), Some(NotReadyReason::ProxyDraining));
}

#[test]
fn capture_reasons_collapse_to_nocapture() {
    for reason in [
        NotReadyReason::CaptureAbsent,
        NotReadyReason::CaptureDraining,
        NotReadyReason::CaptureDetached,
    ] {
        assert_eq!(reason.text_token(), "NOCAPTURE");
    }
}
