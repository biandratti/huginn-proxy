// eBPF/XDP is Linux-only. This crate does not compile for other targets.
#![cfg(target_os = "linux")]
// Unsafe is required in one narrow, documented site:
//   - types.rs: unsafe impl aya::Pod for SynRawDataV4 (kernel memory safety guarantee)
// All other unsafe is denied.
#![deny(unsafe_code)]

pub mod probe;
pub mod types;

pub mod pin;
pub use probe::{
    syn_captured_count_from_path, syn_insert_failures_count_from_path,
    syn_malformed_count_from_path, EbpfProbe, DEFAULT_SYN_MAP_MAX_ENTRIES,
};
pub use types::{parse_syn_v4, parse_syn_v6, quirk_bits, SynRawDataV4, SynRawDataV6};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAttachMode {
    /// Driver-level (default). Requires NIC driver support; falls back silently to skb on older kernels.
    Native,
    /// Generic/SKB mode. Runs in the kernel stack. Works on any interface (veth, loopback, VMs).
    Skb,
}

/// Which BPF hook captures TCP SYNs. Both hooks live in the same ELF and share all maps; the
/// loader attaches exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    /// XDP (`huginn_xdp_syn`). Native or generic/SKB mode. Best on physical/veth interfaces.
    /// On VLAN/bond interfaces only generic XDP attaches, and generic XDP **drops GRO-merged data
    /// packets** for single-buffer programs — use [`CaptureBackend::Tc`] there instead.
    Xdp(XdpAttachMode),
    /// TC clsact ingress (`huginn_tc_syn`). Reads via `bpf_skb_load_bytes` (GRO-safe) and never
    /// drops packets. Works on veth/VLAN/bond/physical alike. Recommended on VLAN/bond edges.
    Tc,
}

#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    #[error("failed to load BPF object: {0}")]
    Load(#[from] aya::EbpfError),

    #[error("BPF program not found in BPF object (expected 'huginn_xdp_syn' or 'huginn_tc_syn')")]
    ProgramNotFound,

    #[error("BPF program has an unexpected type: {0}")]
    ProgramType(#[source] aya::programs::ProgramError),

    #[error("failed to load BPF program into kernel: {0}")]
    ProgramLoad(#[source] aya::programs::ProgramError),

    #[error("failed to attach BPF program to interface: {0}")]
    Attach(#[source] aya::programs::ProgramError),

    #[error("failed to pin BPF map '{name}': {source}")]
    Pin {
        name: String,
        #[source]
        source: aya::pin::PinError,
    },

    #[error("failed to open pinned BPF map at '{path}': {source}")]
    FromPin {
        path: String,
        #[source]
        source: aya::maps::MapError,
    },

    #[error("failed to create pin directory '{path}': {source}")]
    PinDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
