/// Quirk bitmask constants extracted from IP and TCP headers.
///
/// Must match the identical module in `huginn-ebpf/src/types.rs`.
/// Both sides use `offset_of!` compile-time assertions to enforce layout parity.
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
