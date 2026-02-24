//! Types shared between the BPF kernel program and the userspace loader.
//!
//! This crate is `no_std` so it can be compiled for both targets:
//! - `bpfel-unknown-none` (kernel-side XDP program)
//! - the host target (userspace loader in `huginn-proxy-ebpf`)
//!
//! Enable the `aya-pod` feature in the userspace crate to get the
//! `aya::Pod` impl required for reading values out of BPF maps.
#![no_std]

/// Quirk bitmask constants extracted from IP and TCP headers.
///
/// These mirror the `QUIRK_*` macros previously in `bpf/xdp.c`.
/// Used by the XDP program to set bits and by the userspace loader to decode them.
pub mod quirk_bits {
    pub const DF: u32 = 1 << 0; // IP don't-fragment bit (df)
    pub const NONZERO_ID: u32 = 1 << 1; // non-zero IP ID with DF set (id+)
    pub const ZERO_ID: u32 = 1 << 2; // zero IP ID without DF (id-)
    pub const MUST_BE_ZERO: u32 = 1 << 3; // reserved bit in frag_off (0+)
    pub const ECN: u32 = 1 << 4; // ECE or CWR TCP flag (ecn)
    pub const SEQ_ZERO: u32 = 1 << 5; // TCP sequence number zero (seq-)
    pub const ACK_NONZERO: u32 = 1 << 6; // non-zero ACK in SYN (ack+)
    pub const NONZERO_URG: u32 = 1 << 7; // non-zero urgent pointer (uptr+)
    pub const URG: u32 = 1 << 8; // URG flag set (urgf+)
    pub const PUSH: u32 = 1 << 9; // PUSH flag set (pushf+)
}

/// Raw data extracted from a TCP SYN packet by the XDP program.
///
/// **Layout must match `tcp_syn_val` in `xdp.c` exactly** (both `#[repr(C)]`).
///
/// ```text
/// offset  0: src_addr  u32  (network byte order)
/// offset  4: src_port  u16  (network byte order)
/// offset  6: window    u16  (network byte order)
/// offset  8: optlen    u16  (TCP options length captured)
/// offset 10: ip_ttl    u8
/// offset 11: ip_olen   u8   (IP options length: ihl*4 - 20)
/// offset 12: options   [u8; 40]
/// offset 52: quirks    u32  (quirk_bits bitmask)
/// offset 56: tick      u64  (global SYN counter at capture time)
/// ```
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

/// Implement `aya::Pod` so the userspace loader can read `SynRawData` from BPF maps.
/// Only compiled when the `aya-pod` feature is enabled (i.e. in the userspace crate).
///
/// SAFETY: `SynRawData` is `#[repr(C)]`, `Copy`, fully initialized with no implicit padding.
#[cfg(feature = "aya-pod")]
#[allow(unsafe_code)]
unsafe impl aya::Pod for SynRawData {}
