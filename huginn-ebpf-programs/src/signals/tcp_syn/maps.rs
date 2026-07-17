use aya_ebpf::{
    macros::map,
    maps::{Array, LruHashMap, PerCpuArray},
};

use huginn_ebpf_common::constants::{TCP_SYN_MAP_V4_MAX_ENTRIES, TCP_SYN_MAP_V6_MAX_ENTRIES};
use huginn_ebpf_common::{SynRawDataV4, SynRawDataV6};

#[map]
#[allow(non_upper_case_globals)]
pub static tcp_syn_map_v4: LruHashMap<u64, SynRawDataV4> =
    LruHashMap::with_max_entries(TCP_SYN_MAP_V4_MAX_ENTRIES, 0);

// Plain Array (not per-CPU): one global tick for stale detection; cross-CPU races are approximate.
#[map]
#[allow(non_upper_case_globals)]
pub static syn_counter: Array<u64> = Array::with_max_entries(1, 0);

// Family-agnostic metadata: slot 0 holds the shared LRU capacity (max_entries) the agent
// created the SYN maps with. Written by the userspace agent (not the datapath) so the proxy
// can read the staleness threshold without opening any per-family (v4/v6) map.
//
// `#[used]` is required because no BPF program references this map: without it the BPF linker
// dead-strips the global (export_name alone does not keep it), and aya would never create it.
#[used]
#[map]
#[allow(non_upper_case_globals)]
pub static syn_meta: Array<u64> = Array::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_insert_failures_v4: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_captured_v4: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_malformed_v4: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static tcp_syn_map_v6: LruHashMap<[u8; 18], SynRawDataV6> =
    LruHashMap::with_max_entries(TCP_SYN_MAP_V6_MAX_ENTRIES, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_insert_failures_v6: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_captured_v6: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
#[allow(non_upper_case_globals)]
pub static syn_malformed_v6: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[allow(unsafe_code)]
#[inline(always)]
pub fn read_and_increment_syn_counter() -> u64 {
    if let Some(ptr) = syn_counter.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let current = *ptr;
            *ptr = current.wrapping_add(1);
            current
        }
    } else {
        0
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_insert_failures_v4() {
    if let Some(ptr) = syn_insert_failures_v4.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_captured_v4() {
    if let Some(ptr) = syn_captured_v4.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_malformed_v4() {
    if let Some(ptr) = syn_malformed_v4.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_insert_failures_v6() {
    if let Some(ptr) = syn_insert_failures_v6.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_captured_v6() {
    if let Some(ptr) = syn_captured_v6.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn increment_syn_malformed_v6() {
    if let Some(ptr) = syn_malformed_v6.get_ptr_mut(0) {
        // SAFETY: ptr from get_ptr_mut(Some) is a valid map slot.
        unsafe {
            let v = *ptr;
            *ptr = v.wrapping_add(1);
        }
    }
}

// Loader-patched globals; read via read_volatile so the compiler cannot cache pre-patch values.

#[allow(unsafe_code)]
#[export_name = "dst_port"]
static DST_PORT: u16 = 0;

#[allow(unsafe_code)]
#[export_name = "dst_ip_v4"]
static DST_IP_V4: u32 = 0;

#[allow(unsafe_code)]
#[export_name = "dst_ip_v6"]
static DST_IP_V6: [u8; 16] = [0u8; 16];

#[allow(unsafe_code)]
#[inline(always)]
pub fn dst_port() -> u16 {
    // SAFETY: read_volatile of a loader-patched global.
    unsafe { core::ptr::read_volatile(&DST_PORT) }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn dst_ip_v4() -> u32 {
    // SAFETY: read_volatile of a loader-patched global.
    unsafe { core::ptr::read_volatile(&DST_IP_V4) }
}

#[allow(unsafe_code)]
#[inline(always)]
pub fn dst_ip_v6() -> [u8; 16] {
    // SAFETY: read_volatile of a loader-patched global.
    unsafe { core::ptr::read_volatile(&DST_IP_V6) }
}
