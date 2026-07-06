#![no_std]
#![deny(unsafe_code)]

//! Shared logic for TCP SYN fingerprinting between the BPF kernel programs and userspace.
//!
//! Contract: `quirk_bits`, `SynRawDataV4`/`SynRawDataV6` layout, and key encoding must match
//! both `huginn-ebpf-programs` and `huginn-ebpf`.

pub mod constants;
pub mod headers;
pub mod keys;
pub mod quirk_bits;
pub mod syn_raw_v4;
pub mod syn_raw_v6;

pub use keys::{make_key_v4, make_key_v6};
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
