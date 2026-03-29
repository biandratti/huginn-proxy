#![allow(unsafe_code)]

use aya_ebpf::{
    macros::map,
    maps::{Array, LruHashMap},
};

use crate::constants::{TCP_SYN_MAP_V4_MAX_ENTRIES, TCP_SYN_MAP_V6_MAX_ENTRIES};
use huginn_ebpf_common::{SynRawData, SynRawDataV6};

// ── BPF maps (TCP SYN signal — IPv4) ─────────────────────────────────────────

#[map]
#[allow(non_upper_case_globals)]
pub static tcp_syn_map_v4: LruHashMap<u64, SynRawData> =
    LruHashMap::with_max_entries(TCP_SYN_MAP_V4_MAX_ENTRIES, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_counter: Array<u64> = Array::with_max_entries(1, 0);

/// Counter of SYN map insert failures for IPv4 (LRU full or similar).
/// Read by the agent/proxy for observability (e.g. metric `tcp_syn_insert_failures_total`).
#[map]
#[allow(non_upper_case_globals)]
pub static syn_insert_failures_v4: Array<u64> = Array::with_max_entries(1, 0);

/// Counter of successfully captured IPv4 TCP SYN signatures.
/// Incremented when insert into tcp_syn_map_v4 succeeds.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_captured_v4: Array<u64> = Array::with_max_entries(1, 0);

/// Counter of malformed IPv4 TCP packets (e.g. doff too short) that matched dst filter.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_malformed_v4: Array<u64> = Array::with_max_entries(1, 0);

// ── BPF maps (TCP SYN signal — IPv6) ─────────────────────────────────────────

/// LRU map for IPv6 TCP SYN fingerprints, keyed by (src_addr[16] || src_port[2]).
#[map]
#[allow(non_upper_case_globals)]
pub static tcp_syn_map_v6: LruHashMap<[u8; 18], SynRawDataV6> =
    LruHashMap::with_max_entries(TCP_SYN_MAP_V6_MAX_ENTRIES, 0);

/// Counter of IPv6 SYN map insert failures.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_insert_failures_v6: Array<u64> = Array::with_max_entries(1, 0);

/// Counter of successfully captured IPv6 TCP SYN signatures.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_captured_v6: Array<u64> = Array::with_max_entries(1, 0);

/// Counter of malformed IPv6 TCP packets that matched the dst filter.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_malformed_v6: Array<u64> = Array::with_max_entries(1, 0);

// ── Safe wrappers around map counter access ──────────────────────────────────
//
// All unsafe for these arrays is confined here. If get_ptr_mut fails we return a default
// (no panic, no UB). Invalid pointer use would be UB; we only deref when get_ptr_mut
// returned Some (aya guarantees that is a valid map slot).

/// Read and increment the global SYN counter (shared by V4 and V6 for stale detection).
/// Returns the value before increment.
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

/// Increment the insert-failures counter for IPv4 (for observability when map insert fails).
#[inline(always)]
pub fn increment_syn_insert_failures_v4() {
    if let Some(ptr) = syn_insert_failures_v4.get_ptr_mut(0) {
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the syn_captured counter for IPv4 (successful insert into LRU map).
#[inline(always)]
pub fn increment_syn_captured_v4() {
    if let Some(ptr) = syn_captured_v4.get_ptr_mut(0) {
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the syn_malformed counter for IPv4 (TCP packet matched dst but header invalid).
#[inline(always)]
pub fn increment_syn_malformed_v4() {
    if let Some(ptr) = syn_malformed_v4.get_ptr_mut(0) {
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the insert-failures counter for IPv6.
#[inline(always)]
pub fn increment_syn_insert_failures_v6() {
    if let Some(ptr) = syn_insert_failures_v6.get_ptr_mut(0) {
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the syn_captured counter for IPv6.
#[inline(always)]
pub fn increment_syn_captured_v6() {
    if let Some(ptr) = syn_captured_v6.get_ptr_mut(0) {
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the syn_malformed counter for IPv6.
#[inline(always)]
pub fn increment_syn_malformed_v6() {
    if let Some(ptr) = syn_malformed_v6.get_ptr_mut(0) {
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

/// IPv6 destination address filter (all-zeros = accept any destination).
/// Each byte patched at load time by EbpfLoader::set_global.
#[no_mangle]
#[allow(non_upper_case_globals)]
pub static dst_ip_v6: [u8; 16] = [0u8; 16];
