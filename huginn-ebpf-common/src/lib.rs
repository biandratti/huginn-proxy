#![no_std]

//! Shared logic for TCP SYN fingerprinting between the XDP program and userspace.
//!
//! Contract: `quirk_bits`, `SynRawDataV4`/`SynRawDataV6` layout, and key encoding must match
//! both `huginn-ebpf-xdp` and `huginn-ebpf`.

pub mod quirk_bits;
pub mod syn_raw_v4;
pub mod syn_raw_v6;

pub use syn_raw_v4::SynRawDataV4;
pub use syn_raw_v6::SynRawDataV6;

/// Build the BPF map key from source IP and port (IPv4).
///
/// Both `src_ip` and `src_port` are in network byte order as read by the LE CPU.
/// Userspace (`huginn-ebpf`) uses the same encoding in `make_bpf_key_v4`.
#[inline(always)]
pub fn make_key_v4(src_ip: u32, src_port: u16) -> u64 {
    ((src_ip as u64) << 16) | (src_port as u64)
}

/// Build the BPF map key from source IPv6 address and port (kernel side).
///
/// Returns an 18-byte array: the 16-byte address (raw packet bytes, already in NBO)
/// followed by 2 bytes of port in native-endian order, which on a LE CPU recovers
/// the original big-endian wire bytes stored in `tcp->source`.
///
/// `src_addr` is `ip6->saddr` as a byte array — no endianness conversion needed.
/// `src_port` is `tcp->source` as a u16 NBO-as-NE value (raw LE read of BE bytes).
///
/// Userspace (`huginn-ebpf`) uses `make_bpf_key_v6` which reconstructs the same bytes
/// from a host-order port via `to_be_bytes()`.
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
