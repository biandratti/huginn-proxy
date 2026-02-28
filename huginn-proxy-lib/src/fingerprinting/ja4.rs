use huginn_net_tls::Ja4Payload;

/// JA4 fingerprint data extracted from TLS ClientHello
#[derive(Debug, Clone)]
pub struct Ja4Fingerprints {
    /// Normalized JA4 payload
    pub ja4: Ja4Payload,
    /// Not normalized JA4 payload
    pub ja4_raw: Ja4Payload,
    /// Server Name Indication from ClientHello (SNI extension)
    pub sni: Option<String>,
}

impl Ja4Fingerprints {
    pub fn new(ja4: Ja4Payload, ja4_raw: Ja4Payload, sni: Option<String>) -> Self {
        Self { ja4, ja4_raw, sni }
    }
}
