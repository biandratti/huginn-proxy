use huginn_net_db::observable_signals::TcpObservation;
use huginn_net_db::tcp::Quirk;
use huginn_net_tcp::syn_options::parse_options_raw;
use huginn_net_tcp::tcp::{IpVersion, PayloadSize, TcpOption};
use huginn_net_tcp::{ttl, window_size};
use tracing::warn;

/// Results of scanning raw TCP option bytes for quirk-relevant values.
///
/// `parse_options_raw` gives us option *types* and `mss`/`wscale` values but
/// does not expose timestamp values or trailing padding. We scan the bytes once
/// ourselves to fill those gaps.
struct OptionQuirks {
    /// `ts_val` from the Timestamp option (kind=8). `None` if TS not present.
    ts_val: Option<u32>,
    /// `ts_ecr` from the Timestamp option (kind=8). `None` if TS not present.
    ts_ecr: Option<u32>,
    /// Non-zero bytes found after an EOL option — maps to quirk `opt+`.
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
                // EOL: remaining padding bytes should be zero; non-zero → opt+.
                return OptionQuirks {
                    ts_val,
                    ts_ecr,
                    trailing_nonzero: tail.iter().any(|&b| b != 0),
                };
            }
            1 => rest = tail, // NOP: single byte, no length field
            _ => {
                // Options with kind >= 2: kind(1) + len(1) + data(len-2)
                let Some((&len_byte, data)) = tail.split_first() else {
                    break;
                };
                let len = len_byte as usize;
                // len encodes the total option size including kind and len bytes.
                let data_len = len.saturating_sub(2);
                let Some(option_data) = data.get(..data_len) else {
                    break;
                };

                // TS option: kind=8, len=10 → 8 data bytes: ts_val(4) | ts_ecr(4)
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

    // Reached end of buffer without EOL → no trailing non-zero bytes.
    OptionQuirks { ts_val, ts_ecr, trailing_nonzero: false }
}

/// Raw TCP SYN data as extracted by the eBPF XDP program.
///
/// This is a transport type: `huginn-proxy-ebpf` populates it from the BPF map,
/// and this module consumes it to produce a `TcpObservation`.
///
/// All network-byte-order fields (`window`) must be converted before use.
/// Fields that the current XDP program cannot extract are set explicitly by
/// the caller so the constraints are visible at construction time.
#[derive(Debug, Clone)]
pub struct TcpSynData {
    /// TCP window size (network byte order — convert with u16::from_be)
    pub window: u16,
    /// IP TTL (host byte order)
    pub ip_ttl: u8,
    /// Length of valid bytes in `options` (host byte order)
    pub optlen: u16,
    /// Raw TCP options bytes (up to 40 bytes; only `optlen` bytes are valid)
    pub options: [u8; 40],

    // --- Fields set explicitly at the call site; easy to wire in once the XDP program
    // --- is extended to extract them.
    /// IP version of the client connection.
    /// Currently always `V4`; the XDP program filters out non-IPv4 at line ~20 of xdp.c.
    pub ip_version: IpVersion,
    /// Length of IP options in bytes (`ip->ihl * 4 - 20`).
    /// The XDP program already computes `ip_hdr_len`; `olen` just needs to be stored
    /// in `SynRawData` and forwarded here.
    pub olen: u8,
    /// IP/TCP header quirks (DF bit, ECN, zero-seq, non-zero ACK, URG/PUSH flags, …).
    /// Extracted from IP/TCP headers in `xdp.c` and decoded via `decode_quirks` in `main.rs`.
    /// `parse_syn_raw` merges these with option-derived quirks (exws, ts1-, ts2+, opt+).
    pub quirks: Vec<Quirk>,
    /// Payload size classification.
    /// TCP SYN packets never carry a payload, so this is always `PayloadSize::Zero`
    /// by protocol definition — not a limitation.
    pub pclass: PayloadSize,
}

/// Outcome of a TCP SYN fingerprint probe.
///
/// Returned by the [`SynProbe`](crate::proxy::server::SynProbe) closure; lets
/// `server.rs` record a precise metric label for each connection.
#[derive(Debug, Clone)]
pub enum SynResult {
    /// BPF map entry found and successfully parsed.
    Hit(TcpObservation),
    /// No BPF map entry for this peer (keep-alive reuse, IPv6, stale).
    Miss,
    /// BPF map entry found but TCP options bytes were malformed.
    Malformed,
}

/// Parse raw TCP SYN data from the eBPF map.
///
/// Returns `Some(obs)` on success or `None` when options are malformed
/// (`ParsedTcpOptions::malformed`). A `WARN` log is emitted for the latter.
///
/// Callers that need to distinguish miss from malformed should use
/// [`SynResult`] (see `huginn-proxy/src/main.rs`).
pub fn parse_syn_raw(data: &TcpSynData) -> Option<TcpObservation> {
    let window_host = u16::from_be(data.window);
    let valid_opts = &data.options[..data.optlen.min(40) as usize];

    let parsed = parse_options_raw(valid_opts);
    if parsed.malformed {
        warn!(
            optlen = data.optlen,
            partial_opts = ?parsed.olayout,
            "TCP SYN options malformed: truncated or invalid option byte; dropping fingerprint"
        );
        return None;
    }

    let ittl = ttl::calculate_ttl(data.ip_ttl);
    let wsize = window_size::detect_win_multiplicator(
        window_host,
        parsed.mss.unwrap_or(0),
        20 + u16::from(data.olen), // IP header base (20 bytes) + IP options
        parsed.olayout.contains(&TcpOption::TS),
        &data.ip_version,
    );

    // Merge IP/TCP-header quirks (from XDP) with option-derived quirks computed here.
    let mut quirks = data.quirks.clone();

    // exws: window scale > 14 is considered excessive by p0f.
    if parsed.wscale.map(|ws| ws > 14).unwrap_or(false) {
        quirks.push(Quirk::ExcessiveWindowScaling);
    }

    // ts1-, ts2+, opt+: scan raw bytes for values parse_options_raw doesn't expose.
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
        version: data.ip_version,
        ittl,
        olen: data.olen,
        mss: parsed.mss,
        wsize,
        wscale: parsed.wscale,
        olayout: parsed.olayout,
        quirks,
        pclass: data.pclass,
    })
}
