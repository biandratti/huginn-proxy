use huginn_net_db::observable_signals::TcpObservation;
use huginn_net_db::tcp::Quirk;
use huginn_net_tcp::syn_options::parse_options_raw;
use huginn_net_tcp::tcp::{IpVersion, PayloadSize, TcpOption};
use huginn_net_tcp::{ttl, window_size};
use tracing::warn;

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
    /// All are readable from the IP/TCP headers already parsed by the XDP program;
    /// not yet implemented in `xdp.c`.
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

    Some(TcpObservation {
        version: data.ip_version,
        ittl,
        olen: data.olen,
        mss: parsed.mss,
        wsize,
        wscale: parsed.wscale,
        olayout: parsed.olayout,
        quirks: data.quirks.clone(),
        pclass: data.pclass,
    })
}
