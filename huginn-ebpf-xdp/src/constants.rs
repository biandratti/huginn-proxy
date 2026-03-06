// ── Network protocol constants (network byte order on LE host) ────────────────
//
// All EtherType and IP flag values are pre-swapped so that direct comparison
// against the raw u16 fields in packet headers works correctly on a
// little-endian host without calling swap_bytes() at runtime.

// ── EtherType ────────────────────────────────────────────────────────────────

pub const ETH_P_IP: u16 = 0x0800_u16.swap_bytes();
pub const ETH_P_8021Q: u16 = 0x8100_u16.swap_bytes();
pub const ETH_P_8021AD: u16 = 0x88A8_u16.swap_bytes();

// ── IPv4 fragment flags / offset mask ────────────────────────────────────────

pub const IP_RF: u16 = 0x8000_u16.swap_bytes(); // reserved / must-be-zero
pub const IP_DF: u16 = 0x4000_u16.swap_bytes(); // don't fragment
pub const IP_MF: u16 = 0x2000_u16.swap_bytes(); // more fragments
pub const IP_OFFSET: u16 = 0x1FFF_u16.swap_bytes(); // fragment offset mask

// ── IP protocol numbers ───────────────────────────────────────────────────────

pub const IPPROTO_TCP: u8 = 6;

// ── TCP option limits ─────────────────────────────────────────────────────────

pub const TCPOPT_MAXLEN: usize = 40;
