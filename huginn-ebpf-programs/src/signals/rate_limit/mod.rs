//! Per-source-IP SYN rate limiting gate.
//!
//! Runs in both data path hooks (XDP and TC) right after the SYN check and before the expensive
//! TCP-option copy. Over-limit SYNs are skipped, not captured into the `tcp_syn_map_v4/v6` LRU
//! maps, so a single flooding IP cannot saturate them. The packet is never dropped and always
//! passes through to the stack.
//!
//! The counting algorithm lives in the shared `huginn-ebpf-rate-limit` crate; this module only
//! wires it to BPF maps, loader-patched thresholds, and kernel clock.

mod maps;

use aya_ebpf::helpers::bpf_ktime_get_ns;
use huginn_ebpf_rate_limit::{fold_v6, Sketch};

use maps::{
    increment_syn_rate_allowed_v4, increment_syn_rate_allowed_v6, increment_syn_rate_skipped_v4,
    increment_syn_rate_skipped_v6, syn_rate_enabled, syn_rate_sketch_v4, syn_rate_sketch_v6,
    syn_rate_threshold, syn_rate_window_ns,
};

/// Observe one IPv4 SYN from `saddr` and report whether capture should be skipped (over limit).
/// Returns `false` (capture) when rate limiting is disabled or the sketch map is unavailable.
#[allow(unsafe_code)]
#[inline(always)]
pub fn should_skip_v4(saddr: u32) -> bool {
    if !syn_rate_enabled() {
        return false;
    }
    let Some(ptr) = syn_rate_sketch_v4.get_ptr_mut(0) else {
        return false;
    };
    // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot. This is this CPU's private
    // PerCpuArray copy, so the &mut cannot alias another CPU's sketch.
    let sketch: &mut Sketch = unsafe { &mut *ptr };
    let now = unsafe { bpf_ktime_get_ns() };
    let over =
        sketch.observe_over_limit(saddr as u64, now, syn_rate_window_ns(), syn_rate_threshold());
    if over {
        increment_syn_rate_skipped_v4();
    } else {
        increment_syn_rate_allowed_v4();
    }
    over
}

/// Observe one IPv6 SYN from `saddr` and report whether capture should be skipped (over limit).
#[allow(unsafe_code)]
#[inline(always)]
pub fn should_skip_v6(saddr: [u8; 16]) -> bool {
    if !syn_rate_enabled() {
        return false;
    }
    let Some(ptr) = syn_rate_sketch_v6.get_ptr_mut(0) else {
        return false;
    };
    // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot. This is this CPU's private
    // PerCpuArray copy, so the &mut cannot alias another CPU's sketch.
    let sketch: &mut Sketch = unsafe { &mut *ptr };
    let now = unsafe { bpf_ktime_get_ns() };
    let over =
        sketch.observe_over_limit(fold_v6(saddr), now, syn_rate_window_ns(), syn_rate_threshold());
    if over {
        increment_syn_rate_skipped_v6();
    } else {
        increment_syn_rate_allowed_v6();
    }
    over
}
