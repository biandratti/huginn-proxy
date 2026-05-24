use huginn_net_tcp::TcpObservation;

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

impl SynResult {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Hit(_) => "hit",
            Self::Miss => "miss",
            Self::Malformed => "malformed",
        }
    }

    pub fn observation(&self) -> Option<&TcpObservation> {
        if let Self::Hit(obs) = self {
            Some(obs)
        } else {
            None
        }
    }
}
