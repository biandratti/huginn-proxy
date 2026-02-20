use huginn_net_tls::Ja4Payload;

/// JA4 fingerprint data extracted from TLS ClientHello
#[derive(Debug, Clone)]
pub struct Ja4Fingerprints {
    /// Parsed JA4 payload with full fingerprint
    pub ja4: Ja4Payload,
    /// Raw/original JA4 payload
    pub ja4_raw: Ja4Payload,
}

impl Ja4Fingerprints {
    pub fn new(ja4: Ja4Payload, ja4_raw: Ja4Payload) -> Self {
        Self { ja4, ja4_raw }
    }
}
