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

/// Attach mechanism actually used at runtime.
///
/// Distinct from [`CaptureBackend`]: `HUGINN_EBPF_CAPTURE=tc` becomes [`CaptureMode::Tcx`] on
/// kernel ≥ 6.6 (pinnable `bpf_link`) or [`CaptureMode::Netlink`] below (legacy clsact filter,
/// not hitless across agent restarts). XDP labels match the configured backend; whether the
/// XDP attach used an fd link (pinnable) is reported separately via [`crate::EbpfProbe::link_pinned`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// TCX (`bpf_link` + `bpf_mprog`), kernel ≥ 6.6.
    Tcx,
    /// Legacy TC clsact filter via netlink.
    Netlink,
    /// Driver-mode XDP.
    XdpNative,
    /// Generic/SKB XDP.
    XdpSkb,
}

impl CaptureMode {
    /// Prometheus / log label: `tcx` | `netlink` | `xdp-native` | `xdp-skb`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcx => "tcx",
            Self::Netlink => "netlink",
            Self::XdpNative => "xdp-native",
            Self::XdpSkb => "xdp-skb",
        }
    }

    pub(crate) fn from_xdp(mode: XdpAttachMode) -> Self {
        match mode {
            XdpAttachMode::Native => Self::XdpNative,
            XdpAttachMode::Skb => Self::XdpSkb,
        }
    }
}

/// Per-source SYN rate-limit thresholds patched into the BPF program at load time.
///
/// Construct only via [`SynRateLimit::from_burst_window`] or [`SynRateLimit::disabled`]: fields are
/// private so an unenforceable `threshold` (above [`SynRateLimit::MAX_THRESHOLD`]) or a zero window
/// cannot be smuggled past validation.
///
/// `threshold` is the `burst` (max SYNs per window per source before its SYNs stop being
/// captured), `window_ns` is `window_seconds` in nanoseconds. When disabled, every SYN
/// passes through to capture as before.
///
/// Not the proxy's global `[security.rate_limit]`, despite the shared `burst`/`window_seconds`
/// names: this one counts SYNs and is enforced per CPU, so the same number buys a much higher
/// ceiling here. See `EBPF-SETUP.md` for how to size it.
///
/// Scope: over-limit SYNs are skipped (not fingerprinted), never dropped. Protects the
/// `tcp_syn_map_v4/v6` capture LRU from one loud source; not a network-level DoS defense.
/// IPv4 is keyed per address; IPv6 per `/64` prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynRateLimit {
    enabled: bool,
    threshold: u32,
    window_ns: u64,
}

impl SynRateLimit {
    /// Largest enforceable `burst`. Above it the sketch's saturating `u16` counters cannot push the
    /// current window's count past the threshold, so the limiter stops being reliable.
    pub const MAX_THRESHOLD: u32 = huginn_ebpf_rate_limit::MAX_THRESHOLD;

    /// Largest usable `window_seconds` (one hour). Counts never decay inside a window, only when it
    /// rotates, so a source that crosses `burst` has its SYNs skipped until the window ends. The
    /// window length is therefore how long one burst costs a source its fingerprints.
    pub const MAX_WINDOW_SECONDS: u64 = 3600;

    /// A disabled rate limiter (data path gate is a no-op).
    pub const fn disabled() -> Self {
        Self { enabled: false, threshold: 0, window_ns: 0 }
    }

    /// Build from the proxy rate-limit config values: `burst` becomes the threshold and
    /// `window_seconds` is converted to nanoseconds (saturating).
    ///
    /// A zero `burst` or `window_seconds` is nonsensical (threshold 0 would skip every SYN,
    /// window 0 would never rotate), so any such input yields a [`disabled`](Self::disabled)
    /// limiter rather than a footgun. Same for a `burst` above [`Self::MAX_THRESHOLD`], which is
    /// not enforceable, and a `window_seconds` above [`Self::MAX_WINDOW_SECONDS`], which turns the
    /// limiter into a blocklist.
    pub fn from_burst_window(enabled: bool, burst: u32, window_seconds: u64) -> Self {
        if !enabled
            || burst == 0
            || burst > Self::MAX_THRESHOLD
            || window_seconds == 0
            || window_seconds > Self::MAX_WINDOW_SECONDS
        {
            return Self::disabled();
        }
        Self {
            enabled,
            threshold: burst,
            window_ns: window_seconds.saturating_mul(1_000_000_000),
        }
    }

    /// Whether the in-kernel SYN rate limiter is active.
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Max SYNs per window per source before capture is skipped.
    ///
    /// Enforced **per CPU**: the sketch lives in a per-CPU map, so a source whose SYNs land on
    /// multiple RX queues can send up to roughly `threshold * num_cpus` per window before being
    /// skipped. Size it accordingly.
    ///
    /// Always in `1..=`[`SynRateLimit::MAX_THRESHOLD`] when [`enabled`](Self::enabled); `0` when
    /// disabled.
    pub const fn threshold(self) -> u32 {
        self.threshold
    }

    /// Sliding-window length in nanoseconds. `0` when disabled.
    pub const fn window_ns(self) -> u64 {
        self.window_ns
    }
}
