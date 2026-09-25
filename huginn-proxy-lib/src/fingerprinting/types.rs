use huginn_net_http::AkamaiFingerprint;
use huginn_net_tcp::TcpObservation;
use tokio::sync::watch;

use crate::fingerprinting::Ja4Fingerprints;

/// The fingerprints a connection can contribute to each of its requests.
///
/// Every field is `None` when its capture is disabled or does not apply to the
/// transport: plaintext connections have no JA4, HTTP/1.1 yields no Akamai, and a
/// keep-alive request has no fresh SYN. Akamai arrives through a `watch` because
/// [`CapturingStream`](crate::fingerprinting::CapturingStream) extracts it from the
/// HTTP/2 frames after the connection is already being served.
#[derive(Debug, Clone, Default)]
pub struct ConnectionFingerprints {
    pub ja4: Option<Ja4Fingerprints>,
    pub akamai: Option<watch::Receiver<Option<AkamaiFingerprint>>>,
    pub tcp_syn: Option<TcpObservation>,
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
