#![no_std]

//! Shared logic for TCP SYN fingerprinting between the BPF kernel programs and userspace.
//!
//! Contract: `quirk_bits`, `SynRawDataV4`/`SynRawDataV6` layout, and key encoding must match
//! both `huginn-ebpf-programs` and `huginn-ebpf`.

pub mod constants;
pub mod headers;
pub mod quirk_bits;
pub mod syn_raw_v4;
pub mod syn_raw_v6;

pub use syn_raw_v4::SynRawDataV4;
pub use syn_raw_v6::SynRawDataV6;

/// Compile-time string equality for BPF entry-point name assertions.
#[inline]
#[must_use]
pub const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i = i.wrapping_add(1);
    }
    true
}

/// BPF map key (IPv4). Network-byte-order IP and port as read on a LE CPU.
#[inline(always)]
pub fn make_key_v4(src_ip: u32, src_port: u16) -> u64 {
    ((src_ip as u64) << 16) | (src_port as u64)
}

/// BPF map key (IPv6). 16-byte addr + 2-byte port in wire byte order.
#[inline(always)]
pub fn make_key_v6(src_addr: [u8; 16], src_port: u16) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[..16].copy_from_slice(&src_addr);
    // src_port is NBO-as-NE: to_ne_bytes() on a LE CPU recovers the original wire bytes.
    let port_bytes = src_port.to_ne_bytes();
    key[16] = port_bytes[0];
    key[17] = port_bytes[1];
    key
}
