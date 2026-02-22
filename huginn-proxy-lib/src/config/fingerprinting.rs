use serde::Deserialize;

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
    /// Requires the `ebpf-tcp` Cargo feature and `ebpf_tcp_interface` to be set.
    /// When false the eBPF probe is never started, even if the feature is compiled in.
    /// Default: false
    #[serde(default)]
    pub tcp_enabled: bool,
    /// Maximum bytes to capture for HTTP/2 fingerprinting
    /// This limits the amount of data buffered for fingerprint extraction
    /// Default: 65536 (64 KB)
    #[serde(default = "default_max_capture")]
    pub max_capture: usize,
    /// Network interface name for eBPF TCP SYN fingerprinting (e.g. "eth0", "ens3").
    /// Only used when `tcp_enabled = true` and the `ebpf-tcp` feature is compiled in.
    /// Default: None
    #[serde(default)]
    pub ebpf_tcp_interface: Option<String>,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            tls_enabled: default_true(),
            http_enabled: default_true(),
            tcp_enabled: false,
            max_capture: default_max_capture(),
            ebpf_tcp_interface: None,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_capture() -> usize {
    64 * 1024 // 64 KB
}
