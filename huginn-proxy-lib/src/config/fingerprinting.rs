use serde::Deserialize;

/// How the proxy obtains TCP SYN data from eBPF.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TcpMode {
    /// The proxy loads the XDP program and owns the BPF maps (single-process).
    #[default]
    Embedded,
    /// An external eBPF agent owns the XDP program; the proxy opens pinned maps.
    Pinned,
}

/// Fingerprinting configuration
#[derive(Debug, Deserialize, Clone)]
pub struct FingerprintConfig {
    /// Enable TLS fingerprinting (JA4)
    /// Default: true
    #[serde(default = "default_true")]
    pub tls_enabled: bool,
    /// Enable HTTP/2 fingerprinting (Akamai)
    /// Note: Only works for HTTP/2 connections, not HTTP/1.x
    /// Default: true
    #[serde(default = "default_true")]
    pub http_enabled: bool,
    /// Enable TCP SYN fingerprinting via eBPF/XDP (p0f-style raw signature).
    /// Requires the `ebpf-tcp` Cargo feature and the `HUGINN_EBPF_INTERFACE`,
    /// `HUGINN_EBPF_DST_IP`, and `HUGINN_EBPF_DST_PORT` environment variables.
    /// When false the eBPF probe is never started, even if the feature is compiled in.
    /// Default: false
    #[serde(default)]
    pub tcp_enabled: bool,
    /// How to obtain TCP SYN data when `tcp_enabled = true`.
    /// - `embedded` (default): the proxy loads XDP and owns the maps.
    /// - `pinned`: an external eBPF agent owns XDP; the proxy opens pinned maps.
    #[serde(default)]
    pub tcp_mode: TcpMode,
    /// Maximum bytes to capture for HTTP/2 fingerprinting
    /// This limits the amount of data buffered for fingerprint extraction
    /// Default: 65536 (64 KB)
    #[serde(default = "default_max_capture")]
    pub max_capture: usize,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            tls_enabled: default_true(),
            http_enabled: default_true(),
            tcp_enabled: false,
            tcp_mode: TcpMode::default(),
            max_capture: default_max_capture(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_capture() -> usize {
    64 * 1024 // 64 KB
}
