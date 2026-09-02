use huginn_ebpf::pin;
use huginn_ebpf_agent::healthchecks::{AgentHealth, NotReadyReason, REQUIRED_PINS};

#[test]
fn capture_state_is_not_a_required_pin() {
    assert!(
        !REQUIRED_PINS.contains(&pin::CAPTURE_STATE_NAME),
        "capture_state must not be in REQUIRED_PINS so a legacy agent without the map stays ready"
    );
}

/// A name the loader never pins can never appear, so `/ready` would stay 503 forever.
/// Deliberately a subset check: telemetry-only maps are pinned but do not gate readiness.
#[test]
fn every_required_pin_is_one_the_loader_actually_pins() {
    for name in REQUIRED_PINS {
        assert!(
            pin::ALL_NAMES.contains(name),
            "/ready requires '{name}', but it is not in pin::ALL_NAMES so the loader never \
             pins it; readiness would never turn ready"
        );
    }
}

#[test]
fn not_attached_is_capture_detached() {
    let health = AgentHealth::new("/no/such/pins".into(), "/no/such/link".into());
    assert_eq!(health.not_ready_reason(), Some(NotReadyReason::CaptureDetached));
}

#[test]
fn draining_outranks_detached() {
    let health = AgentHealth::new("/no/such/pins".into(), "/no/such/link".into());
    health.mark_draining();
    assert_eq!(health.not_ready_reason(), Some(NotReadyReason::CaptureDraining));
}

#[test]
fn mark_attached_cannot_cancel_draining() {
    let health = AgentHealth::new("/no/such/pins".into(), "/no/such/link".into());
    health.mark_draining();
    health.mark_attached(false);
    assert!(!health.is_ready());
    assert_eq!(health.not_ready_reason(), Some(NotReadyReason::CaptureDraining));
}

#[test]
fn attached_without_pins_is_pins_not_ready() {
    let health = AgentHealth::new("/no/such/pins".into(), "/no/such/link".into());
    health.mark_attached(false);
    assert_eq!(health.not_ready_reason(), Some(NotReadyReason::PinsNotReady));
}
