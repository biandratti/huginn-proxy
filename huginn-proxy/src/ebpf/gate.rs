use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use huginn_ebpf::{pin, read_capture_state, CaptureState};
use huginn_proxy_lib::GateState;

pub fn store_gate(slot: &AtomicU8, state: GateState) {
    slot.store(state as u8, Ordering::Release);
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
    let state = match read_capture_state(pin_path) {
        Ok(state) => state,
        Err(_) => return GateState::Absent,
    };
    if !state.is_published() {
        return GateState::Absent;
    }
    if state.is_draining() {
        return GateState::Draining;
    }
    if Path::new(link_pin_path).exists() {
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
