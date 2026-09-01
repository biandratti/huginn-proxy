use huginn_ebpf::{pin, CaptureState};
use huginn_proxy::ebpf::gate::decide;
use huginn_proxy_lib::GateState;

const STALE_TICKS: u32 = 3;

struct Heartbeat {
    last_generation: Option<u64>,
    stagnant_ticks: u32,
}

impl Heartbeat {
    fn new() -> Self {
        Self { last_generation: None, stagnant_ticks: 0 }
    }

    fn tick(&mut self, state: CaptureState, link_exists: bool) -> GateState {
        decide(
            state,
            link_exists,
            &mut self.last_generation,
            &mut self.stagnant_ticks,
            STALE_TICKS,
        )
    }
}

fn draining(boot_id: u64, generation: u64) -> CaptureState {
    CaptureState { generation, lifecycle: pin::CAPTURE_LIFECYCLE_DRAINING, boot_id }
}

#[test]
fn unpublished_state_outranks_draining() {
    let mut heartbeat = Heartbeat::new();
    assert_eq!(heartbeat.tick(draining(0, 42), true), GateState::Absent);
}

#[test]
fn draining_outranks_a_pinned_link() {
    let mut heartbeat = Heartbeat::new();
    assert_eq!(heartbeat.tick(draining(7, 42), true), GateState::Draining);
}

#[test]
fn a_pinned_link_stays_ready_through_a_frozen_heartbeat() {
    let mut heartbeat = Heartbeat::new();
    let state = CaptureState::capturing(7, 42);
    for _ in 0..(STALE_TICKS * 2) {
        assert_eq!(heartbeat.tick(state, true), GateState::Ready);
    }
}

#[test]
fn an_unpinned_frozen_heartbeat_goes_detached_after_stale_ticks() {
    let mut heartbeat = Heartbeat::new();
    let state = CaptureState::capturing(7, 42);

    assert_eq!(heartbeat.tick(state, false), GateState::Ready, "first poll only records");
    for tick in 1..STALE_TICKS {
        assert_eq!(heartbeat.tick(state, false), GateState::Ready, "tick {tick} of {STALE_TICKS}");
    }
    assert_eq!(heartbeat.tick(state, false), GateState::Detached);
}

#[test]
fn an_unpinned_advancing_heartbeat_stays_ready() {
    let mut heartbeat = Heartbeat::new();
    for generation in 0..(u64::from(STALE_TICKS) * 2) {
        assert_eq!(heartbeat.tick(CaptureState::capturing(7, generation), false), GateState::Ready);
    }
}

/// A netlink agent that stalls and recovers must come back on its own, without a proxy restart.
#[test]
fn a_resumed_heartbeat_recovers_from_detached() {
    let mut heartbeat = Heartbeat::new();
    for _ in 0..=STALE_TICKS {
        heartbeat.tick(CaptureState::capturing(7, 42), false);
    }
    assert_eq!(heartbeat.tick(CaptureState::capturing(7, 42), false), GateState::Detached);
    assert_eq!(heartbeat.tick(CaptureState::capturing(7, 43), false), GateState::Ready);
}
