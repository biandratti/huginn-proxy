use huginn_net_db::observable_signals::TcpObservation;

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
