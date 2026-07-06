use aya_ebpf::{
    macros::map,
    maps::{Array, LruHashMap, PerCpuArray},
};

use huginn_ebpf_common::constants::{TCP_SYN_MAP_V4_MAX_ENTRIES, TCP_SYN_MAP_V6_MAX_ENTRIES};
use huginn_ebpf_common::{SynRawDataV4, SynRawDataV6};

// ── BPF maps (TCP SYN signal — IPv4) ─────────────────────────────────────────

#[map]
#[allow(non_upper_case_globals)]
pub static tcp_syn_map_v4: LruHashMap<u64, SynRawDataV4> =
    LruHashMap::with_max_entries(TCP_SYN_MAP_V4_MAX_ENTRIES, 0);

/// Global SYN counter (shared across V4 and V6) used as a monotonic "tick" for stale detection.
/// Intentionally a plain `Array` (not per-CPU) because it needs a single global sequence; the
/// cross-CPU increment is non-atomic and therefore approximate, which the 2× map-size stale
/// threshold in the reader absorbs.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_counter: Array<u64> = Array::with_max_entries(1, 0);

/// Counter of SYN map insert failures for IPv4 (LRU full or similar).
/// Read by the agent/proxy for observability (e.g. metric `tcp_syn_insert_failures_total`).
#[map]
#[allow(non_upper_case_globals)]
pub static syn_insert_failures_v4: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Counter of successfully captured IPv4 TCP SYN signatures.
/// Incremented when insert into tcp_syn_map_v4 succeeds.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_captured_v4: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Counter of malformed IPv4 TCP packets (e.g. doff too short) that matched dst filter.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_malformed_v4: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// ── BPF maps (TCP SYN signal — IPv6) ─────────────────────────────────────────

/// LRU map for IPv6 TCP SYN fingerprints, keyed by (src_addr[16] || src_port[2]).
#[map]
#[allow(non_upper_case_globals)]
pub static tcp_syn_map_v6: LruHashMap<[u8; 18], SynRawDataV6> =
    LruHashMap::with_max_entries(TCP_SYN_MAP_V6_MAX_ENTRIES, 0);

/// Counter of IPv6 SYN map insert failures.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_insert_failures_v6: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Counter of successfully captured IPv6 TCP SYN signatures.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_captured_v6: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Counter of malformed IPv6 TCP packets that matched the dst filter.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_malformed_v6: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// ── Safe wrappers around map counter access ──────────────────────────────────
//
// All unsafe for these arrays is confined to these fns (each carries its own
// `#[allow(unsafe_code)]`). If get_ptr_mut fails we return a default (no panic, no UB). We only
// deref when get_ptr_mut returned Some (aya guarantees that is a valid map slot).
//
// The six observability counters are `PerCpuArray`, so `get_ptr_mut(0)` returns *this CPU's* slot:
// the increment is genuinely uniquely-owned (no other CPU touches it) and race-free. The reader in
// the loader sums the per-CPU slots. `syn_counter` is the one exception (plain `Array`, see above).

/// Read and increment the global SYN counter (shared by V4 and V6 for stale detection).
/// Returns the value before increment.
#[allow(unsafe_code)]
#[inline(always)]
pub fn read_and_increment_syn_counter() -> u64 {
    if let Some(ptr) = syn_counter.get_ptr_mut(0) {
        // SAFETY: ptr came from get_ptr_mut(Some) → a valid, uniquely-owned map slot.
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
#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_insert_failures_v4() {
    if let Some(ptr) = syn_insert_failures_v4.get_ptr_mut(0) {
        // SAFETY: ptr came from get_ptr_mut(Some) → a valid, uniquely-owned map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the syn_captured counter for IPv4 (successful insert into LRU map).
#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_captured_v4() {
    if let Some(ptr) = syn_captured_v4.get_ptr_mut(0) {
        // SAFETY: ptr came from get_ptr_mut(Some) → a valid, uniquely-owned map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the syn_malformed counter for IPv4 (TCP packet matched dst but header invalid).
#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_malformed_v4() {
    if let Some(ptr) = syn_malformed_v4.get_ptr_mut(0) {
        // SAFETY: ptr came from get_ptr_mut(Some) → a valid, uniquely-owned map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the insert-failures counter for IPv6.
#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_insert_failures_v6() {
    if let Some(ptr) = syn_insert_failures_v6.get_ptr_mut(0) {
        // SAFETY: ptr came from get_ptr_mut(Some) → a valid, uniquely-owned map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the syn_captured counter for IPv6.
#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_captured_v6() {
    if let Some(ptr) = syn_captured_v6.get_ptr_mut(0) {
        // SAFETY: ptr came from get_ptr_mut(Some) → a valid, uniquely-owned map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

/// Increment the syn_malformed counter for IPv6.
#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_malformed_v6() {
    if let Some(ptr) = syn_malformed_v6.get_ptr_mut(0) {
        // SAFETY: ptr came from get_ptr_mut(Some) → a valid, uniquely-owned map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

// ── Globals patched at load time by EbpfLoader::override_global ──────────────
//
// The loader patches these read-only globals (by exported symbol name) before the
// program loads. The statics are private; the capture pipelines read them through the
// accessor fns below, which wrap `read_volatile` (so the compiler cannot cache the
// pre-patch value) and keep that `unsafe` confined to this module.

#[allow(unsafe_code)]
#[export_name = "dst_port"]
static DST_PORT: u16 = 0;

/// IPv4 destination address filter (`0` = accept any destination).
#[allow(unsafe_code)]
#[export_name = "dst_ip_v4"]
static DST_IP_V4: u32 = 0;

/// IPv6 destination address filter (all-zeros = accept any destination).
#[allow(unsafe_code)]
#[export_name = "dst_ip_v6"]
static DST_IP_V6: [u8; 16] = [0u8; 16];

/// Read the loader-patched destination port filter (network byte order; `0` = any).
#[allow(unsafe_code)]
#[inline(always)]
pub fn dst_port() -> u16 {
    // SAFETY: read_volatile of a loader-patched read-only global; no aliasing, prevents caching.
    unsafe { core::ptr::read_volatile(&DST_PORT) }
}

/// Read the loader-patched IPv4 destination filter (`0` = any).
#[allow(unsafe_code)]
#[inline(always)]
pub fn dst_ip_v4() -> u32 {
    // SAFETY: read_volatile of a loader-patched read-only global; no aliasing, prevents caching.
    unsafe { core::ptr::read_volatile(&DST_IP_V4) }
}

/// Read the loader-patched IPv6 destination filter (all-zeros = any).
#[allow(unsafe_code)]
#[inline(always)]
pub fn dst_ip_v6() -> [u8; 16] {
    // SAFETY: read_volatile of a loader-patched read-only global; no aliasing, prevents caching.
    unsafe { core::ptr::read_volatile(&DST_IP_V6) }
}
