// ── Network protocol constants (network byte order on LE host) ────────────────
//
// All EtherType and IP flag values are pre-swapped so that direct comparison
// against the raw u16 fields in packet headers works correctly on a
// little-endian host without calling swap_bytes() at runtime.

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

// ── IP ToS ECN bits (RFC 3168) ─────────────────────────────────────────────────

pub const IP_TOS_CE: u8 = 0x01;  // Congestion Experienced
pub const IP_TOS_ECT: u8 = 0x02; // ECN-Capable Transport

// ── IP protocol numbers ───────────────────────────────────────────────────────

pub const IPPROTO_TCP: u8 = 6;

// ── TCP option limits ─────────────────────────────────────────────────────────

pub const TCPOPT_MAXLEN: usize = 40;

// ── TCP SYN map capacity ─────────────────────────────────────────────────────
//
// Max entries for the LRU map that stores one SynRawData per (src_ip, src_port).
// Value taken from the ebpf-web-fingerprint reference (data/ebpf-web-fingerprint);
// no rationale documented there. We keep it as a power-of-two (2^13) and a
// reasonable default for concurrent SYN flows. huginn-ebpf uses 2× this for
// STALE_TICK_THRESHOLD when deciding if a map entry is stale (see probe.rs).

pub const TCP_SYN_MAP_V4_MAX_ENTRIES: u32 = 8192;
pub const TCP_SYN_MAP_V6_MAX_ENTRIES: u32 = 8192;
