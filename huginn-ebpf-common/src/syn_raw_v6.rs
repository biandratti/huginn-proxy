//! Raw data extracted from an IPv6 TCP SYN packet, stored in the BPF LRU map.
//!
//! Layout is the single source of truth for both `huginn-ebpf-xdp` and `huginn-ebpf`.
//!
//! ```text
//! offset  0: src_addr  [u8; 16]  (network byte order, IPv6 address)
//! offset 16: src_port  u16       (network byte order)
//! offset 18: window    u16       (network byte order)
//! offset 20: optlen    u8        (actual TCP option bytes copied; max 40)
//! offset 21: ip_tos    u8        (IPv6 traffic class byte; bits 0-1 are ECN CE/ECT)
//! offset 22: ip_ttl    u8        (IPv6 hop_limit)
//! offset 23: _pad      u8        (always 0; ip_olen has no IPv6 equivalent)
//! offset 24: options   [u8; 40]
//! offset 64: quirks    u32       (quirk_bits bitmask; DF/ID quirks absent for IPv6)
//! offset 68: tick      u64       (global SYN counter at capture time; shared with V4)
//! total: 76 bytes
//! ```

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SynRawDataV6 {
    pub src_addr: [u8; 16],
    pub src_port: u16,
    pub window: u16,
    pub optlen: u8,
    pub ip_tos: u8,
    pub ip_ttl: u8,
    pub _pad: u8,
    pub options: [u8; 40],
    pub quirks: u32,
    pub tick: u64,
}

impl Default for SynRawDataV6 {
    fn default() -> Self {
        Self {
            src_addr: [0u8; 16],
            src_port: 0,
            window: 0,
            optlen: 0,
            ip_tos: 0,
            ip_ttl: 0,
            _pad: 0,
            options: [0u8; 40],
            quirks: 0,
            tick: 0,
        }
    }
}

/// SAFETY: `SynRawDataV6` is `#[repr(C)]`, `Copy`, fully initialized with no implicit padding.
#[cfg(feature = "aya")]
#[allow(unsafe_code)]
unsafe impl aya::Pod for SynRawDataV6 {}
