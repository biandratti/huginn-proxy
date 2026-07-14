use serde::{Deserialize, Serialize};

/// Fingerprinting configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
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
    /// Requires the `ebpf-tcp` Cargo feature and the `huginn-ebpf-agent`
    /// running on the same node with pinned maps at `HUGINN_EBPF_PIN_PATH`.
    /// When false the proxy does not open BPF maps.
    /// Default: false
    #[serde(default)]
    pub tcp_enabled: bool,
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

/// Allowlisted effective-config view of [`FingerprintConfig`]. Field names are the JSON keys.
#[derive(Serialize)]
pub(crate) struct FingerprintView {
    tls_enabled: bool,
    http_enabled: bool,
    tcp_enabled: bool,
    max_capture: usize,
}

impl FingerprintConfig {
    pub(crate) fn effective_view(&self) -> FingerprintView {
        FingerprintView {
            tls_enabled: self.tls_enabled,
            http_enabled: self.http_enabled,
            tcp_enabled: self.tcp_enabled,
            max_capture: self.max_capture,
        }
    }
}
