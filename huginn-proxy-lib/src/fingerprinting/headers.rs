/// HTTP header names for fingerprint injection
///
/// These constants define the header names used to inject fingerprints
pub mod names {
    /// Header name for TLS (JA4) fingerprint injection
    ///
    /// This header contains the JA4 fingerprint normalized from the TLS ClientHello.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4: &str = "x-huginn-net-ja4";

    /// Header name for TLS JA4_r fingerprint injection (FoxIO naming)
    ///
    /// JA4_r: cipher suites and extensions in original ClientHello order, SHA-256 hashed.
    /// Differs from JA4 only in sort order of the B and C components.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_R: &str = "x-huginn-net-ja4_r";

    /// Header name for TLS JA4_o fingerprint injection (FoxIO naming)
    ///
    /// JA4_o: cipher suites and extensions sorted, raw (not hashed) hex values.
    /// Useful for debugging and forensic analysis without needing to reverse a hash.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_O: &str = "x-huginn-net-ja4_o";

    /// Header name for TLS JA4_or fingerprint injection (FoxIO naming)
    ///
    /// JA4_or: cipher suites and extensions in original ClientHello order, raw (not hashed) hex values.
    /// Combines original order and raw values - maximum detail for analysis.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_OR: &str = "x-huginn-net-ja4_or";

    /// Header name for HTTP/2 (Akamai) fingerprint injection
    ///
    /// This header contains the Akamai-style fingerprint extracted from HTTP/2 frames.
    /// It is only injected for HTTP/2 connections when fingerprinting is enabled.
    pub const HTTP2_AKAMAI: &str = "x-huginn-net-akamai";

    /// Header name for TCP SYN p0f-style raw signature injection
    ///
    /// This header contains the raw TCP SYN fingerprint extracted via eBPF/XDP.
    /// Format: `"ver:ittl:olen:mss:wsize,wscale:olayout"`
    /// Example: `"4:64:0:1460:8192,6:mss,nop,ws,nop,nop,ts,sok"`
    /// Only injected when the `ebpf-tcp` feature is enabled and fingerprinting is configured.
    pub const TCP_SYN: &str = "x-huginn-net-tcp";
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
