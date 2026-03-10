//! Quirk bitmask constants for TCP SYN fingerprinting (p0f-style).
//!
//! Must match the decode side in `huginn-ebpf` (e.g. `decode_quirks` in types.rs).

pub const DF: u32 = 1 << 0;
pub const NONZERO_ID: u32 = 1 << 1;
pub const ZERO_ID: u32 = 1 << 2;
pub const MUST_BE_ZERO: u32 = 1 << 3;
pub const ECN: u32 = 1 << 4;
pub const SEQ_ZERO: u32 = 1 << 5;
pub const ACK_NONZERO: u32 = 1 << 6;
pub const NONZERO_URG: u32 = 1 << 7;
pub const URG: u32 = 1 << 8;
pub const PUSH: u32 = 1 << 9;
