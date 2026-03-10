#![no_std]

//! Shared logic for TCP SYN fingerprinting between the XDP program and userspace.
//!
//! Contract: `quirk_bits`, `SynRawData` layout, and `make_key` encoding must match
//! both `huginn-ebpf-xdp` and `huginn-ebpf`.

pub mod quirk_bits;
pub mod syn_raw;

pub use syn_raw::SynRawData;

/// Build the BPF map key from source IP and port (IPv4).
///
/// Both `src_ip` and `src_port` are in network byte order as read by the LE CPU.
/// Userspace (`huginn-ebpf`) uses the same encoding in `make_bpf_key`.
#[inline(always)]
pub fn make_key(src_ip: u32, src_port: u16) -> u64 {
    ((src_ip as u64) << 16) | (src_port as u64)
}
