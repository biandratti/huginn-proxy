/// HTTP header names for fingerprint injection
///
/// These constants define the header names used to inject fingerprints
pub mod names {
    /// Header name for TLS (JA4) fingerprint injection
    ///
    /// This header contains the JA4 fingerprint extracted from the TLS ClientHello.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4: &str = "x-huginn-net-ja4";

    /// Header name for HTTP/2 (Akamai) fingerprint injection
    ///
    /// This header contains the Akamai-style fingerprint extracted from HTTP/2 frames.
    /// It is only injected for HTTP/2 connections when fingerprinting is enabled.
    pub const HTTP2_AKAMAI: &str = "x-huginn-net-akamai";
}
