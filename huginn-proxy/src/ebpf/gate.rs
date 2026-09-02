use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use huginn_ebpf::{pin, read_capture_state, CaptureState};
use huginn_proxy_lib::GateState;

pub fn store_gate(slot: &AtomicU8, state: GateState) {
    let previous = GateState::from_u8(slot.swap(state as u8, Ordering::Release));
    if previous != state {
        tracing::info!(from = previous.as_str(), to = state.as_str(), "capture gate changed");
    }
}

pub fn load_gate(slot: &Arc<AtomicU8>) -> GateState {
    GateState::from_u8(slot.load(Ordering::Acquire))
}

/// Resolve capture health for `/ready`.
///
/// Priority: announced drain, then a pinned bpf_link, then generation heartbeat (legacy).
pub fn resolve(
    pin_path: &str,
    link_pin_path: &str,
    last_generation: &mut Option<u64>,
    stagnant_ticks: &mut u32,
    stale_ticks: u32,
) -> GateState {
    let Ok(state) = read_capture_state(pin_path) else {
        return GateState::Absent;
    };
    decide(
        state,
        Path::new(link_pin_path).exists(),
        last_generation,
        stagnant_ticks,
        stale_ticks,
    )
}

/// The priority itself, over an already-read snapshot.
///
/// Separate from [`resolve`] so it can be tested without bpffs: `read_capture_state` needs a
/// real pinned map, and this ordering is what decides whether the node stays in the load
/// balancer.
pub fn decide(
    state: CaptureState,
    link_exists: bool,
    last_generation: &mut Option<u64>,
    stagnant_ticks: &mut u32,
    stale_ticks: u32,
) -> GateState {
    if !state.is_published() {
        return GateState::Absent;
    }
    if state.is_draining() {
        return GateState::Draining;
    }
    if link_exists {
        *last_generation = Some(state.generation);
        *stagnant_ticks = 0;
        return GateState::Ready;
    }
    if heartbeat_stale(state, last_generation, stagnant_ticks, stale_ticks) {
        GateState::Detached
    } else {
        GateState::Ready
    }
}

fn heartbeat_stale(
    state: CaptureState,
    last_generation: &mut Option<u64>,
    stagnant_ticks: &mut u32,
    stale_ticks: u32,
) -> bool {
    match *last_generation {
        Some(prev) if prev == state.generation => {
            *stagnant_ticks = stagnant_ticks.saturating_add(1);
            *stagnant_ticks >= stale_ticks
        }
        _ => {
            *last_generation = Some(state.generation);
            *stagnant_ticks = 0;
            false
        }
    }
}

pub fn default_link_pin_path(pin_path: &str) -> String {
    std::env::var("HUGINN_EBPF_LINK_PIN_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| pin::capture_link_path(pin_path).display().to_string())
}
