//! Network protocol constants shared between the BPF kernel programs and userspace tests.
//!
//! EtherType and IPv4 flag values are pre-swapped with `.swap_bytes()` so they can be
//! compared directly against the raw `u16` fields in packet headers on a little-endian
//! CPU without calling `swap_bytes()` at runtime.

// ── EtherType ────────────────────────────────────────────────────────────────

pub const ETH_P_IPV4: u16 = 0x0800_u16.swap_bytes();
pub const ETH_P_IPV6: u16 = 0x86DD_u16.swap_bytes();
pub const ETH_P_8021Q: u16 = 0x8100_u16.swap_bytes();
pub const ETH_P_8021AD: u16 = 0x88A8_u16.swap_bytes();

// ── IPv4 fragment flags / offset mask ────────────────────────────────────────

pub const IP_RF: u16 = 0x8000_u16.swap_bytes(); // reserved / must-be-zero
pub const IP_DF: u16 = 0x4000_u16.swap_bytes(); // don't fragment
pub const IP_MF: u16 = 0x2000_u16.swap_bytes(); // more fragments
pub const IP_OFFSET: u16 = 0x1FFF_u16.swap_bytes(); // fragment offset mask

// ── IP ToS ECN bits (RFC 3168) ────────────────────────────────────────────────

pub const IP_TOS_CE: u8 = 0x01; // Congestion Experienced
pub const IP_TOS_ECT: u8 = 0x02; // ECN-Capable Transport

// ── IP protocol numbers ───────────────────────────────────────────────────────

pub const IPPROTO_TCP: u8 = 6;

// ── TCP option limits ─────────────────────────────────────────────────────────

/// Maximum bytes of TCP options we read and store (TCP header max is 40 bytes).
pub const TCPOPT_MAXLEN: usize = 40;

// ── TCP SYN map capacity ──────────────────────────────────────────────────────
//
// Default LRU map sizes. `huginn-ebpf` uses 2× this as the stale-entry threshold
// (see `probe.rs`). The agent can override via `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`.

pub const TCP_SYN_MAP_V4_MAX_ENTRIES: u32 = 8192;
pub const TCP_SYN_MAP_V6_MAX_ENTRIES: u32 = 8192;
