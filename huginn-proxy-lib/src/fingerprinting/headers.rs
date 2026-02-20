/// HTTP header names for fingerprint injection
///
/// These constants define the header names used to inject fingerprints
pub mod names {
    /// Header name for TLS (JA4) fingerprint injection
    ///
    /// This header contains the JA4 fingerprint extracted from the TLS ClientHello.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4: &str = "x-huginn-net-ja4";

    /// Header name for TLS (JA4) raw fingerprint injection
    ///
    /// This header contains the raw/original JA4 fingerprint string.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_RAW: &str = "x-huginn-net-ja4-raw";

    /// Header name for HTTP/2 (Akamai) fingerprint injection
    ///
    /// This header contains the Akamai-style fingerprint extracted from HTTP/2 frames.
    /// It is only injected for HTTP/2 connections when fingerprinting is enabled.
    pub const HTTP2_AKAMAI: &str = "x-huginn-net-akamai";
}

/// HTTP header names for X-Forwarded-* headers
///
/// These constants define the header names used for proxy forwarding information.
/// They are injected by the proxy to inform backends about the original client request.
pub mod forwarded {
    /// Header name for X-Forwarded-For
    ///
    /// Contains the client IP address(es) in a comma-separated list.
    /// Each proxy in the chain appends the client IP it received the request from.
    pub const FOR: &str = "x-forwarded-for";

    /// Header name for X-Forwarded-Host
    ///
    /// Contains the original Host header value from the client request.
    pub const HOST: &str = "x-forwarded-host";

    /// Header name for X-Forwarded-Port
    ///
    /// Contains the original port number from the client request.
    pub const PORT: &str = "x-forwarded-port";

    /// Header name for X-Forwarded-Proto
    ///
    /// Contains the protocol used by the client ("http" or "https").
    pub const PROTO: &str = "x-forwarded-proto";
}
