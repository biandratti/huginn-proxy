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
