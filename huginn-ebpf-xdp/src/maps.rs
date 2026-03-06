use aya_ebpf::{
    macros::map,
    maps::{Array, LruHashMap},
};

use super::syn_raw::SynRawData;

// ── BPF maps ──────────────────────────────────────────────────────────────────

#[map]
#[allow(non_upper_case_globals)]
pub static tcp_syn_map_v4: LruHashMap<u64, SynRawData> = LruHashMap::with_max_entries(8192, 0); //TODO: check limits

#[map]
#[allow(non_upper_case_globals)]
pub static syn_counter: Array<u64> = Array::with_max_entries(1, 0);

// ── Globals patched at load time by EbpfLoader::set_global ───────────────────
//
// These are `.rodata` variables written by the userspace loader before the
// program is attached to the interface. XDP reads them via read_volatile to
// prevent the compiler from caching the values in a register.

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static dst_port: u16 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static dst_ip: u32 = 0;
