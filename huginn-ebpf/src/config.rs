//! Capture backend and XDP attach mode configuration.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAttachMode {
    /// Driver-level (default). Requires NIC driver XDP support.
    Native,
    /// Generic/SKB mode. Runs in the kernel stack.
    Skb,
}

/// Which BPF hook captures TCP SYNs. Both hooks share the same ELF and maps; the loader attaches one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    /// XDP (`huginn_xdp_syn`). On VLAN/bond edges prefer [`CaptureBackend::Tc`] (generic XDP drops GRO-merged packets).
    Xdp(XdpAttachMode),
    /// TC clsact ingress (`huginn_tc_syn`). GRO-safe via `bpf_skb_load_bytes`.
    Tc,
}

impl CaptureBackend {
    /// Canonical string label used for parsing and logging (e.g. `HUGINN_EBPF_CAPTURE`).
    pub fn as_str(self) -> &'static str {
        match self {
            CaptureBackend::Xdp(XdpAttachMode::Native) => "xdp-native",
            CaptureBackend::Xdp(XdpAttachMode::Skb) => "xdp-skb",
            CaptureBackend::Tc => "tc",
        }
    }
}

/// Per-source-IP SYN rate-limit thresholds patched into the BPF program at load time.
///
/// These mirror the proxy's global `[security.rate_limit]` config: `threshold` is the
/// `burst` (max SYNs per window per source IP before its SYNs stop being captured), `window_ns`
/// is `window_seconds` in nanoseconds. When `enabled` is false, every SYN passes through to
/// capture as before.
///
/// Scope: over-limit SYNs are skipped (not fingerprinted), never dropped. Protects the
/// `tcp_syn_map_v4/v6` capture LRU from one loud source IP; not a network-level DoS defense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynRateLimit {
    /// Whether the in-kernel SYN rate limiter is active.
    pub enabled: bool,
    /// Max SYNs per window per source IP. SYNs beyond this are skipped (not captured into the
    /// fingerprint map); the packet itself always passes through to the stack — never dropped.
    ///
    /// Enforced **per CPU**: the sketch lives in a per-CPU map, so a source IP whose SYNs land on
    /// multiple RX queues can send up to roughly `threshold * num_cpus` per window before being
    /// skipped. Size it accordingly.
    pub threshold: u32,
    /// Sliding-window length in nanoseconds.
    pub window_ns: u64,
}

impl SynRateLimit {
    /// A disabled rate limiter (data path gate is a no-op).
    pub const fn disabled() -> Self {
        Self { enabled: false, threshold: 0, window_ns: 0 }
    }

    /// Build from the proxy rate-limit config values: `burst` becomes the threshold and
    /// `window_seconds` is converted to nanoseconds (saturating).
    ///
    /// A zero `burst` or `window_seconds` is nonsensical (threshold 0 would skip every SYN,
    /// window 0 would never rotate), so any such input yields a [`disabled`](Self::disabled)
    /// limiter rather than a footgun.
    pub fn from_burst_window(enabled: bool, burst: u32, window_seconds: u64) -> Self {
        if !enabled || burst == 0 || window_seconds == 0 {
            return Self::disabled();
        }
        Self {
            enabled,
            threshold: burst,
            window_ns: window_seconds.saturating_mul(1_000_000_000),
        }
    }
}
