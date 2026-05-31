/// HTTP header names for fingerprint injection
///
/// These constants define the header names used to inject fingerprints
pub mod names {
    /// Header name for TLS (JA4) fingerprint injection
    ///
    /// This header contains the JA4 fingerprint normalized from the TLS ClientHello.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4: &str = "x-tls-ja4";

    /// Header name for TLS JA4_r fingerprint injection (FoxIO naming)
    ///
    /// JA4_r: cipher suites and extensions sorted, raw (not hashed) hex values.
    /// Useful for debugging and forensic analysis without needing to reverse a hash.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_R: &str = "x-tls-ja4-r";

    /// Header name for TLS JA4_o fingerprint injection (FoxIO naming)
    ///
    /// JA4_o: cipher suites and extensions in original ClientHello order, SHA-256 hashed.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_O: &str = "x-tls-ja4-o";

    /// Header name for TLS JA4_or fingerprint injection (FoxIO naming)
    ///
    /// JA4_or: cipher suites and extensions in original ClientHello, raw (not hashed) hex values.
    /// Combines original order and raw values - maximum detail for analysis.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_OR: &str = "x-tls-ja4-or";

    /// Header name for TLS JA4_s1 stable fingerprint injection (huginn-net-tls Stable v1)
    ///
    /// JA4_s1: cipher suites and extensions sorted, SHA-256 hashed, ephemeral extensions
    /// excluded (session ticket 0x0023, pre-shared key 0x0029, padding 0x0015).
    /// Yields more consistent fingerprints across resumptions from
    /// the same client than plain JA4, at the cost of omitting signal from those extensions.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_S1: &str = "x-tls-ja4-s1";

    /// Header name for TLS JA4_s1r stable fingerprint injection (raw variant)
    ///
    /// JA4_s1r: same ephemeral-extension filtering as JA4_s1, cipher suites and extensions
    /// sorted, raw (not hashed) hex values.
    /// It is injected for all TLS connections when fingerprinting is enabled.
    pub const TLS_JA4_S1R: &str = "x-tls-ja4-s1r";

    /// Header name for HTTP/2 (Akamai) fingerprint injection
    ///
    /// This header contains the Akamai-style fingerprint extracted from HTTP/2 frames.
    /// It is only injected for HTTP/2 connections when fingerprinting is enabled.
    pub const HTTP2_AKAMAI: &str = "x-http2-akamai";

    /// Header name for TCP SYN p0f-style raw signature injection
    ///
    /// This header contains the raw TCP SYN fingerprint extracted via eBPF/XDP.
    /// Format: `"ver:ittl:olen:mss:wsize,wscale:olayout"`
    /// Example: `"4:64:0:1460:8192,6:mss,nop,ws,nop,nop,ts,sok"`
    /// Only injected when the `ebpf-tcp` feature is enabled and fingerprinting is configured.
    pub const TCP_SYN: &str = "x-tcp-p0f";

    /// All proxy-authoritative fingerprint headers.
    ///
    /// Written exclusively by the proxy from data observed on the connection
    /// (TLS ClientHello, HTTP/2 frames, TCP SYN). A client must never supply them,
    /// they are stripped unconditionally on entry before any are (re)injected.
    pub const FINGERPRINTS: &[&str] = &[
        TLS_JA4,
        TLS_JA4_R,
        TLS_JA4_O,
        TLS_JA4_OR,
        TLS_JA4_S1,
        TLS_JA4_S1R,
        HTTP2_AKAMAI,
        TCP_SYN,
    ];

    /// Header injected toward the backend listing which fingerprint signatures the
    /// client attempted to spoof (comma-separated). Absent when no spoofing is detected.
    ///
    /// Example: [`SPOOFING_DETECTED`]: [`HTTP2_AKAMAI`],[`TCP_SYN`]
    ///
    /// This header is itself proxy-authoritative: it is stripped from client input so
    /// the client cannot forge or suppress the detection signal.
    pub const SPOOFING_DETECTED: &str = "x-fingerprint-spoofing-detected";
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
