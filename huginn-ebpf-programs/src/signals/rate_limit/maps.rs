//! BPF maps and settings for per-source SYN rate limiting.
//!
//! Each sketch (one for IPv4, one for IPv6) lives in a single-entry `PerCpuArray` map: every CPU
//! gets its own private copy, so the datapath can update it in place through a pointer with no
//! locking or atomics. The cost is that the limit is enforced per CPU (see `huginn-ebpf-rate-limit`
//! crate docs). Agent overwrites the threshold globals with the real config when it loads the
//! program.
//!
//! Pinning: the sketch maps are not pinned (absent from `huginn_ebpf::pin::ALL_NAMES`) - ephemeral
//! per-CPU state, correctly reset on each agent (re)load. The `syn_rate_skipped_*`/`syn_rate_allowed_*`
//! counters below are pinned, so their totals survive restarts.

use aya_ebpf::{macros::map, maps::PerCpuArray};
use huginn_ebpf_rate_limit::Sketch;

#[map]
#[allow(non_upper_case_globals)]
pub static syn_rate_sketch_v4: PerCpuArray<Sketch> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_rate_sketch_v6: PerCpuArray<Sketch> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_rate_skipped_v4: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_rate_skipped_v6: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_rate_allowed_v4: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_rate_allowed_v6: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[allow(unsafe_code)]
#[export_name = "syn_rate_enabled"]
static SYN_RATE_ENABLED: u8 = 0;

#[allow(unsafe_code)]
#[export_name = "syn_rate_threshold"]
static SYN_RATE_THRESHOLD: u32 = 0;

#[allow(unsafe_code)]
#[export_name = "syn_rate_window_ns"]
static SYN_RATE_WINDOW_NS: u64 = 0;

#[allow(unsafe_code)]
#[export_name = "syn_rate_seed"]
static SYN_RATE_SEED: u64 = 0;

#[allow(unsafe_code)]
#[inline(always)]
pub fn syn_rate_enabled() -> bool {
    // SAFETY: read_volatile of a loader-patched global.
    unsafe { core::ptr::read_volatile(&SYN_RATE_ENABLED) != 0 }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn syn_rate_threshold() -> u32 {
    // SAFETY: read_volatile of a loader-patched global.
    unsafe { core::ptr::read_volatile(&SYN_RATE_THRESHOLD) }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn syn_rate_window_ns() -> u64 {
    // SAFETY: read_volatile of a loader-patched global.
    unsafe { core::ptr::read_volatile(&SYN_RATE_WINDOW_NS) }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn syn_rate_seed() -> u64 {
    // SAFETY: read_volatile of a loader-patched global.
    unsafe { core::ptr::read_volatile(&SYN_RATE_SEED) }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_rate_skipped_v4() {
    if let Some(ptr) = syn_rate_skipped_v4.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_rate_skipped_v6() {
    if let Some(ptr) = syn_rate_skipped_v6.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_rate_allowed_v4() {
    if let Some(ptr) = syn_rate_allowed_v4.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_rate_allowed_v6() {
    if let Some(ptr) = syn_rate_allowed_v6.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}
