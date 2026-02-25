use huginn_net_db::observable_signals::TcpObservation;
use huginn_net_db::tcp::Quirk;
use huginn_net_tcp::syn_options::parse_options_raw;
use huginn_net_tcp::tcp::{IpVersion, PayloadSize, TcpOption};
use huginn_net_tcp::{ttl, window_size};
use tracing::warn;

/// Quirk bitmask constants extracted from IP and TCP headers.
///
/// Must match the identical module in `huginn-proxy-ebpf-xdp/src/main.rs`.
/// The `offset_of!` block below enforces layout parity at compile time.
pub mod quirk_bits {
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
}

/// Raw data extracted from a TCP SYN packet by the XDP program.
///
/// Layout must match `SynRawData` in `huginn-proxy-ebpf-xdp/src/main.rs` exactly.
/// Both sides use identical `offset_of!` compile-time assertions to enforce this.
/// The canonical layout is documented in `data/huginn-proxy-analisis/bpf.md`.
///
/// ```text
/// offset  0: src_addr  u32  (network byte order)
/// offset  4: src_port  u16  (network byte order)
/// offset  6: window    u16  (network byte order)
/// offset  8: optlen    u16  (TCP options length captured)
/// offset 10: ip_ttl    u8
/// offset 11: ip_olen   u8   (IP options length: ihl*4 - 20)
/// offset 12: options   [u8; 40]
/// offset 52: quirks    u32  (quirk_bits bitmask)
/// offset 56: tick      u64  (global SYN counter at capture time)
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SynRawData {
    pub src_addr: u32,
    pub src_port: u16,
    pub window: u16,
    pub optlen: u16,
    pub ip_ttl: u8,
    pub ip_olen: u8,
    pub options: [u8; 40],
    pub quirks: u32,
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

/// SAFETY: `SynRawData` is `#[repr(C)]`, `Copy`, fully initialized with no implicit padding.
#[allow(unsafe_code)]
unsafe impl aya::Pod for SynRawData {}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SynRawData>() == 64);
    assert!(offset_of!(SynRawData, src_addr) == 0);
    assert!(offset_of!(SynRawData, src_port) == 4);
    assert!(offset_of!(SynRawData, window) == 6);
    assert!(offset_of!(SynRawData, optlen) == 8);
    assert!(offset_of!(SynRawData, ip_ttl) == 10);
    assert!(offset_of!(SynRawData, ip_olen) == 11);
    assert!(offset_of!(SynRawData, options) == 12);
    assert!(offset_of!(SynRawData, quirks) == 52);
    assert!(offset_of!(SynRawData, tick) == 56);
};

// ── Internal parsing helpers ─────────────────────────────────────────────────

struct OptionQuirks {
    ts_val: Option<u32>,
    ts_ecr: Option<u32>,
    trailing_nonzero: bool,
}

/// Scan raw TCP option bytes for values needed to derive option-based quirks.
///
/// Uses slice operations instead of index arithmetic to satisfy
/// `clippy::arithmetic_side_effects`. Assumes the bytes are already validated
/// as non-malformed by `parse_options_raw`.
fn scan_option_quirks(opts: &[u8]) -> OptionQuirks {
    let mut rest = opts;
    let mut ts_val = None;
    let mut ts_ecr = None;

    while let Some((&kind, tail)) = rest.split_first() {
        match kind {
            0 => {
                return OptionQuirks {
                    ts_val,
                    ts_ecr,
                    trailing_nonzero: tail.iter().any(|&b| b != 0),
                };
            }
            1 => rest = tail,
            _ => {
                let Some((&len_byte, data)) = tail.split_first() else {
                    break;
                };
                let len = len_byte as usize;
                let data_len = len.saturating_sub(2);
                let Some(option_data) = data.get(..data_len) else {
                    break;
                };
                if kind == 8 && len == 10 {
                    if let (Some(v), Some(e)) = (option_data.get(..4), option_data.get(4..8)) {
                        ts_val = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
                        ts_ecr = Some(u32::from_be_bytes([e[0], e[1], e[2], e[3]]));
                    }
                }
                let Some(next) = data.get(data_len..) else {
                    break;
                };
                rest = next;
            }
        }
    }

    OptionQuirks { ts_val, ts_ecr, trailing_nonzero: false }
}

fn decode_quirks(bits: u32) -> Vec<Quirk> {
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

// ── Public API ───────────────────────────────────────────────────────────────

/// Parse a TCP SYN fingerprint from raw XDP-captured data.
///
/// Returns `Some(TcpObservation)` on success, or `None` when TCP options are
/// malformed (`ParsedTcpOptions::malformed`). A `WARN` log is emitted for the latter.
///
/// Constants hardcoded from XDP invariants:
/// - `ip_version = V4`: the XDP program filters out non-IPv4 at entry.
/// - `pclass = Zero`: TCP SYN packets never carry a payload by protocol definition.
pub fn parse_syn(raw: &SynRawData) -> Option<TcpObservation> {
    let window_host = u16::from_be(raw.window);
    let valid_opts = &raw.options[..raw.optlen.min(40) as usize];

    let parsed = parse_options_raw(valid_opts);
    if parsed.malformed {
        warn!(
            optlen = raw.optlen,
            partial_opts = ?parsed.olayout,
            "TCP SYN options malformed: truncated or invalid option byte; dropping fingerprint"
        );
        return None;
    }

    let ittl = ttl::calculate_ttl(raw.ip_ttl);
    let wsize = window_size::detect_win_multiplicator(
        window_host,
        parsed.mss.unwrap_or(0),
        20 + u16::from(raw.ip_olen),
        parsed.olayout.contains(&TcpOption::TS),
        &IpVersion::V4,
    );

    let mut quirks = decode_quirks(raw.quirks);

    if parsed.wscale.map(|ws| ws > 14).unwrap_or(false) {
        quirks.push(Quirk::ExcessiveWindowScaling);
    }

    let oq = scan_option_quirks(valid_opts);
    if oq.ts_val == Some(0) {
        quirks.push(Quirk::OwnTimestampZero);
    }
    if oq.ts_ecr.map(|v| v != 0).unwrap_or(false) {
        quirks.push(Quirk::PeerTimestampNonZero);
    }
    if oq.trailing_nonzero {
        quirks.push(Quirk::TrailinigNonZero);
    }

    Some(TcpObservation {
        version: IpVersion::V4,
        ittl,
        olen: raw.ip_olen,
        mss: parsed.mss,
        wsize,
        wscale: parsed.wscale,
        olayout: parsed.olayout,
        quirks,
        pclass: PayloadSize::Zero,
    })
}
