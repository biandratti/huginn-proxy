use huginn_net_db::tcp::Quirk;

/// Quirk bitmask constants for `SynRawData.quirks`.
///
/// These mirror the `QUIRK_*` macros in `huginn-proxy-ebpf/scripts/bpf/xdp.c`.
/// Both sides **must** stay in sync: if a bit is added here, add the matching
/// `#define` in `xdp.c` at the same bit position.
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

/// Raw data extracted from a TCP SYN packet via the XDP eBPF program.
///
/// This is a mirror of the `tcp_syn_val` C struct in `bpf/xdp.c`.
/// The layout must match exactly — both are `#[repr(C)]` with the same field order.
///
/// Layout (64 bytes):
/// ```text
/// offset  0: src_addr  u32  (network byte order)
/// offset  4: src_port  u16  (network byte order)
/// offset  6: window    u16  (network byte order)
/// offset  8: optlen    u16  (TCP options length)
/// offset 10: ip_ttl    u8
/// offset 11: ip_olen   u8   (IP options length: ip->ihl*4 - 20)
/// offset 12: options   [u8; 40]
/// offset 52: quirks    u32  (QUIRK_* bitmask from IP/TCP headers)
/// offset 56: tick      u64  (global SYN counter at capture time)
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SynRawData {
    /// Source IP address (network byte order)
    pub src_addr: u32,
    /// Source port (network byte order)
    pub src_port: u16,
    /// TCP window size (network byte order)
    pub window: u16,
    /// Length of captured TCP options
    pub optlen: u16,
    /// IP TTL
    pub ip_ttl: u8,
    /// IP options length in bytes: `ip->ihl * 4 - 20` (0 = standard header)
    pub ip_olen: u8,
    /// Raw TCP options bytes (up to 40 bytes)
    pub options: [u8; 40],
    /// Quirk bitmask from IP and TCP headers.
    /// Bit layout is defined in [`quirk_bits`]; use [`SynRawData::decode_quirks`] to decode.
    pub quirks: u32,
    /// Global SYN counter value at the moment this packet was captured.
    /// Used by userspace to detect stale map entries.
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

impl SynRawData {
    /// Decode the `quirks` bitmask into a list of [`Quirk`] variants.
    ///
    /// The bit layout is defined in [`quirk_bits`] and must match `QUIRK_*` in `xdp.c`.
    pub fn decode_quirks(&self) -> Vec<Quirk> {
        let bits = self.quirks;
        let mut v = Vec::new();
        if bits & quirk_bits::DF != 0 {
            v.push(Quirk::Df);
        }
        if bits & quirk_bits::NONZERO_ID != 0 {
            v.push(Quirk::NonZeroID);
        }
        if bits & quirk_bits::ZERO_ID != 0 {
            v.push(Quirk::ZeroID);
        }
        if bits & quirk_bits::MUST_BE_ZERO != 0 {
            v.push(Quirk::MustBeZero);
        }
        if bits & quirk_bits::ECN != 0 {
            v.push(Quirk::Ecn);
        }
        if bits & quirk_bits::SEQ_ZERO != 0 {
            v.push(Quirk::SeqNumZero);
        }
        if bits & quirk_bits::ACK_NONZERO != 0 {
            v.push(Quirk::AckNumNonZero);
        }
        if bits & quirk_bits::NONZERO_URG != 0 {
            v.push(Quirk::NonZeroURG);
        }
        if bits & quirk_bits::URG != 0 {
            v.push(Quirk::Urg);
        }
        if bits & quirk_bits::PUSH != 0 {
            v.push(Quirk::Push);
        }
        v
    }
}

// SAFETY: SynRawData is #[repr(C)], Copy, with all fields fully initialized (no implicit padding).
// It can be safely read from/written to BPF maps via aya.
#[allow(unsafe_code)]
unsafe impl aya::Pod for SynRawData {}
