use huginn_net_db::observable_signals::TcpObservation;
use huginn_net_db::tcp::{Quirk, Ttl, WindowSize};
use huginn_net_tcp::syn_options::{parse_options_raw, ParsedTcpOptions};
use huginn_net_tcp::tcp::{IpVersion, PayloadSize, TcpOption};
use huginn_net_tcp::{ttl, window_size};
use tracing::warn;

pub use huginn_ebpf_common::{quirk_bits, SynRawDataV4, SynRawDataV6};

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

/// Parse a TCP SYN fingerprint from raw XDP-captured IPv6 data.
///
/// Returns `Some(TcpObservation)` on success, or `None` when TCP options are
/// malformed. A `WARN` log is emitted for the latter.
///
/// Constants hardcoded from XDP IPv6 invariants:
/// - `ip_version = V6`: only IPv6 SYN packets are stored in `tcp_syn_map_v6`.
/// - `pclass = Zero`: TCP SYN packets never carry a payload.
/// - `ip_olen = 0`: IPv6 has no IP options (extension headers not tracked yet).
/// - `ip_plus_tcp = 60`: IPv6 fixed header (40 bytes) + TCP fixed header (20 bytes).
pub fn parse_syn_v6(raw: &SynRawDataV6) -> Option<TcpObservation> {
    let window_host = u16::from_be(raw.window);
    let valid_opts = &raw.options[..usize::from(raw.optlen.min(40))];

    let parsed: ParsedTcpOptions = parse_options_raw(valid_opts);
    if parsed.malformed {
        warn!(
            optlen = raw.optlen,
            partial_opts = ?parsed.olayout,
            "IPv6 TCP SYN options malformed: truncated or invalid option byte; dropping fingerprint"
        );
        return None;
    }

    let ittl: Ttl = ttl::calculate_ttl(raw.ip_ttl);
    // IPv6 fixed header is 40 bytes; no IP options.
    let ip_plus_tcp: u16 = 60;
    let wsize: WindowSize = window_size::detect_win_multiplicator(
        window_host,
        parsed.mss.unwrap_or(0),
        ip_plus_tcp,
        parsed.olayout.contains(&TcpOption::TS),
        &IpVersion::V6,
    );

    let mut quirks: Vec<Quirk> = decode_quirks(raw.quirks);

    if parsed.wscale.map(|ws| ws > 14).unwrap_or(false) {
        quirks.push(Quirk::ExcessiveWindowScaling);
    }

    let oq: OptionQuirks = scan_option_quirks(valid_opts);
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
        version: IpVersion::V6,
        ittl,
        olen: 0,
        mss: parsed.mss,
        wsize,
        wscale: parsed.wscale,
        olayout: parsed.olayout,
        quirks,
        pclass: PayloadSize::Zero,
    })
}

/// Parse a TCP SYN fingerprint from raw XDP-captured data.
///
/// Returns `Some(TcpObservation)` on success, or `None` when TCP options are
/// malformed (`ParsedTcpOptions::malformed`). A `WARN` log is emitted for the latter.
///
/// Constants hardcoded from XDP invariants:
/// - `ip_version = V4`: the XDP program filters out non-IPv4 at entry.
/// - `pclass = Zero`: TCP SYN packets never carry a payload by protocol definition.
pub fn parse_syn_v4(raw: &SynRawDataV4) -> Option<TcpObservation> {
    let window_host = u16::from_be(raw.window);
    let valid_opts = &raw.options[..usize::from(raw.optlen.min(40))];

    let parsed: ParsedTcpOptions = parse_options_raw(valid_opts);
    if parsed.malformed {
        warn!(
            optlen = raw.optlen,
            partial_opts = ?parsed.olayout,
            "TCP SYN options malformed: truncated or invalid option byte; dropping fingerprint"
        );
        return None;
    }

    let ittl: Ttl = ttl::calculate_ttl(raw.ip_ttl);
    let ip_plus_tcp = 20_u16
        .saturating_add(u16::from(raw.ip_olen))
        .saturating_add(20);
    let wsize: WindowSize = window_size::detect_win_multiplicator(
        window_host,
        parsed.mss.unwrap_or(0),
        ip_plus_tcp,
        parsed.olayout.contains(&TcpOption::TS),
        &IpVersion::V4,
    );

    let mut quirks: Vec<Quirk> = decode_quirks(raw.quirks);

    if parsed.wscale.map(|ws| ws > 14).unwrap_or(false) {
        quirks.push(Quirk::ExcessiveWindowScaling);
    }

    let oq: OptionQuirks = scan_option_quirks(valid_opts);
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
