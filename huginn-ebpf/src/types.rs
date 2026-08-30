use huginn_net_tcp::syn_options::{parse_options_raw, ParsedTcpOptions};
use huginn_net_tcp::tcp::{IpVersion, PayloadSize, Quirk, QuirkSet, Ttl};
use huginn_net_tcp::ttl;
use huginn_net_tcp::TcpObservation;
use tracing::warn;

pub use huginn_ebpf_common::{quirk_bits, SynRawDataV4, SynRawDataV6};

struct OptionQuirks {
    ts_val: Option<u32>,
    ts_ecr: Option<u32>,
    trailing_nonzero: bool,
}

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

fn decode_quirks(bits: u32) -> QuirkSet {
    let mut set = QuirkSet::EMPTY;
    if bits & quirk_bits::DF != 0 {
        set.insert(Quirk::Df);
    }
    if bits & quirk_bits::NONZERO_ID != 0 {
        set.insert(Quirk::NonZeroID);
    }
    if bits & quirk_bits::ZERO_ID != 0 {
        set.insert(Quirk::ZeroID);
    }
    if bits & quirk_bits::MUST_BE_ZERO != 0 {
        set.insert(Quirk::MustBeZero);
    }
    if bits & quirk_bits::ECN != 0 {
        set.insert(Quirk::Ecn);
    }
    if bits & quirk_bits::SEQ_ZERO != 0 {
        set.insert(Quirk::SeqNumZero);
    }
    if bits & quirk_bits::ACK_NONZERO != 0 {
        set.insert(Quirk::AckNumNonZero);
    }
    if bits & quirk_bits::NONZERO_URG != 0 {
        set.insert(Quirk::NonZeroURG);
    }
    if bits & quirk_bits::URG != 0 {
        set.insert(Quirk::Urg);
    }
    if bits & quirk_bits::PUSH != 0 {
        set.insert(Quirk::Push);
    }
    set
}

fn apply_option_quirks(quirks: &mut QuirkSet, valid_opts: &[u8], wscale: Option<u8>) {
    if wscale.map(|ws| ws > 14).unwrap_or(false) {
        quirks.insert(Quirk::ExcessiveWindowScaling);
    }

    let oq: OptionQuirks = scan_option_quirks(valid_opts);
    if oq.ts_val == Some(0) {
        quirks.insert(Quirk::OwnTimestampZero);
    }
    if oq.ts_ecr.map(|v| v != 0).unwrap_or(false) {
        quirks.insert(Quirk::PeerTimestampNonZero);
    }
    if oq.trailing_nonzero {
        quirks.insert(Quirk::TrailinigNonZero);
    }
}

/// DSCP from the IP ToS / traffic-class byte (bits 2–7).
fn dscp_from_tos(ip_tos: u8) -> u8 {
    ip_tos.wrapping_shr(2)
}

pub fn parse_syn_v6(raw: &SynRawDataV6) -> Option<TcpObservation> {
    let window_host = u16::from_be(raw.window);
    let optlen = raw.optlen.min(40);
    let valid_opts = &raw.options[..usize::from(optlen)];

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
    // IPv6 fixed header (40) + TCP header including options (20 + optlen).
    let tot_hdr = 40_u16
        .saturating_add(20)
        .saturating_add(u16::from(optlen));

    let mut quirks = decode_quirks(raw.quirks);
    apply_option_quirks(&mut quirks, valid_opts, parsed.wscale);

    Some(TcpObservation {
        version: IpVersion::V6,
        ittl,
        olen: 0,
        mss: parsed.mss,
        wsize: window_host,
        tot_hdr,
        wscale: parsed.wscale,
        olayout: parsed.olayout,
        quirks,
        pclass: PayloadSize::Zero,
        peer_mss: None,
        tos: dscp_from_tos(raw.ip_tos),
    })
}

pub fn parse_syn_v4(raw: &SynRawDataV4) -> Option<TcpObservation> {
    let window_host = u16::from_be(raw.window);
    let optlen = raw.optlen.min(40);
    let valid_opts = &raw.options[..usize::from(optlen)];

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
    // IP header (20 + ip_olen) + TCP header including options (20 + optlen).
    let tot_hdr = 20_u16
        .saturating_add(u16::from(raw.ip_olen))
        .saturating_add(20)
        .saturating_add(u16::from(optlen));

    let mut quirks = decode_quirks(raw.quirks);
    apply_option_quirks(&mut quirks, valid_opts, parsed.wscale);

    Some(TcpObservation {
        version: IpVersion::V4,
        ittl,
        olen: raw.ip_olen,
        mss: parsed.mss,
        wsize: window_host,
        tot_hdr,
        wscale: parsed.wscale,
        olayout: parsed.olayout,
        quirks,
        pclass: PayloadSize::Zero,
        peer_mss: None,
        tos: dscp_from_tos(raw.ip_tos),
    })
}
