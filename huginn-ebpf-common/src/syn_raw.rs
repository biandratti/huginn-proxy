//! Raw data extracted from a TCP SYN packet, stored in the BPF LRU map.
//!
//! Layout is the single source of truth for both `huginn-ebpf-xdp` and `huginn-ebpf`.
//!
//! ```text
//! offset  0: src_addr  u32  (network byte order)
//! offset  4: src_port  u16  (network byte order)
//! offset  6: window    u16  (network byte order)
//! offset  8: optlen    u16  (TCP options length captured)
//! offset 10: ip_ttl    u8
//! offset 11: ip_olen   u8   (IP options length: ihl*4 - 20)
//! offset 12: options   [u8; 40]
//! offset 52: quirks    u32  (quirk_bits bitmask)
//! offset 56: tick      u64  (global SYN counter at capture time)
//! ```

#[repr(C)]
#[derive(Clone, Copy, Debug)]
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

impl Default for SynRawData {
    fn default() -> Self {
        Self {
            src_addr: 0,
            src_port: 0,
            window: 0,
            optlen: 0,
            ip_ttl: 0,
            ip_olen: 0,
            options: [0u8; 40],
            quirks: 0,
            tick: 0,
        }
    }
}

/// SAFETY: `SynRawData` is `#[repr(C)]`, `Copy`, fully initialized with no implicit padding.
#[cfg(feature = "aya")]
#[allow(unsafe_code)]
unsafe impl aya::Pod for SynRawData {}

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
