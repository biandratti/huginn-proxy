use huginn_ebpf::{pin, CaptureState};

const BOOT_ID: u64 = 0xC0FFEE;

#[test]
fn a_fresh_agent_publishes_capturing() {
    let state = CaptureState::capturing(BOOT_ID, 1);
    assert!(state.is_published());
    assert!(!state.is_draining());
    assert_eq!(state.lifecycle, pin::CAPTURE_LIFECYCLE_CAPTURING);
}

/// `0` is what a legacy agent (no `capture_state` map) and a wiped bpffs both leave behind, so
/// the gate must read it as "nobody published", not as a live agent on generation 0.
#[test]
fn boot_id_zero_is_the_unpublished_sentinel() {
    let state =
        CaptureState { generation: 7, lifecycle: pin::CAPTURE_LIFECYCLE_CAPTURING, boot_id: 0 };
    assert!(!state.is_published());
}

#[test]
fn draining_is_read_from_the_lifecycle_slot() {
    let state = CaptureState {
        generation: 3,
        lifecycle: pin::CAPTURE_LIFECYCLE_DRAINING,
        boot_id: BOOT_ID,
    };
    assert!(state.is_draining());
    assert!(state.is_published());
}

#[test]
fn only_the_publishing_agent_owns_the_pin() {
    let state = CaptureState::capturing(BOOT_ID, 1);
    assert!(state.owned_by(BOOT_ID));
    assert!(!state.owned_by(BOOT_ID.wrapping_add(1)));
}

/// The outgoing agent of a rollout must not write to a pin the incoming one already took over:
/// announcing drain there would 503 every proxy on the node while capture is healthy.
#[test]
fn a_replaced_agent_no_longer_owns_the_pin() {
    let successor = CaptureState::capturing(BOOT_ID.wrapping_add(1), 1);
    assert!(!successor.owned_by(BOOT_ID));
}

/// Nobody owns an unpublished pin, including a caller that somehow carries a zero id.
/// `new_agent_boot_id` never returns `0`, so this only guards against a wiped map.
#[test]
fn an_unpublished_pin_is_owned_by_nobody() {
    let state =
        CaptureState { generation: 0, lifecycle: pin::CAPTURE_LIFECYCLE_CAPTURING, boot_id: 0 };
    assert!(!state.owned_by(0));
}
