#![allow(unsafe_code)]

use aya_ebpf::{
    macros::map,
    maps::{Array, LruHashMap},
};

use huginn_ebpf_common::SynRawData;

// ── BPF maps (TCP SYN signal) ─────────────────────────────────────────────────

#[map]
#[allow(non_upper_case_globals)]
pub static tcp_syn_map_v4: LruHashMap<u64, SynRawData> = LruHashMap::with_max_entries(8192, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_counter: Array<u64> = Array::with_max_entries(1, 0);

/// Counter of SYN map insert failures (LRU full or similar).
/// Read by the agent/proxy for observability (e.g. metric `tcp_syn_insert_failures_total`).
#[map]
#[allow(non_upper_case_globals)]
pub static syn_insert_failures: Array<u64> = Array::with_max_entries(1, 0);

// ── Safe wrappers around map counter access ──────────────────────────────────
//
// All unsafe for these arrays is confined here. If get_ptr_mut fails we return a default
// (no panic, no UB). Invalid pointer use would be UB; we only deref when get_ptr_mut
// returned Some (aya guarantees that is a valid map slot).

/// Read and increment the global SYN counter. Returns the value before increment.
#[inline(always)]
pub fn read_and_increment_syn_counter() -> u64 {
    if let Some(ptr) = syn_counter.get_ptr_mut(0) {
        unsafe {
            let current = *ptr;
            *ptr = current.wrapping_add(1);
            current
        }
    } else {
        0
    }
}

/// Increment the insert-failures counter (for observability when map insert fails).
#[inline(always)]
pub fn increment_syn_insert_failures() {
    if let Some(ptr) = syn_insert_failures.get_ptr_mut(0) {
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

// ── Globals patched at load time by EbpfLoader::set_global ───────────────────
//
// XDP reads them via read_volatile to prevent the compiler from caching.

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static dst_port: u16 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static dst_ip: u32 = 0;
