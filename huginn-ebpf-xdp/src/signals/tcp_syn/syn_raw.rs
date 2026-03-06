/// Raw data extracted from a TCP SYN packet, stored in the BPF LRU map.
///
/// Layout must match `SynRawData` in `huginn-ebpf/src/types.rs` exactly.
/// Both sides use identical `offset_of!` compile-time assertions to enforce this.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SynRawData {
    pub src_addr: u32,
    pub src_port: u16,
    pub window: u16,
    pub optlen: u16,
    pub ip_ttl: u8,
    pub ip_olen: u8,
    pub options: [u8; 40],
    pub quirks: u32,
    pub tick: u64,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SynRawData>() == 64);
    assert!(offset_of!(SynRawData, src_addr) == 0);
    assert!(offset_of!(SynRawData, src_port) == 4);
    assert!(offset_of!(SynRawData, window) == 6);
    assert!(offset_of!(SynRawData, optlen) == 8);
    assert!(offset_of!(SynRawData, ip_ttl) == 10);
    assert!(offset_of!(SynRawData, ip_olen) == 11);
    assert!(offset_of!(SynRawData, options) == 12);
    assert!(offset_of!(SynRawData, quirks) == 52);
    assert!(offset_of!(SynRawData, tick) == 56);
};

/// Build the BPF map key from source IP and port (IPv4).
///
/// Both `src_ip` and `src_port` are in network byte order as read by the LE
/// CPU. The userspace side (`huginn-ebpf`) replicates this encoding in `make_bpf_key`.
#[inline(always)]
pub fn make_key(src_ip: u32, src_port: u16) -> u64 {
    ((src_ip as u64) << 16) | (src_port as u64)
}
