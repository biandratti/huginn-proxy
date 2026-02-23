// eBPF/XDP is Linux-only. This crate does not compile for other targets.
#![cfg(target_os = "linux")]

pub mod probe;
pub mod types;

pub use probe::EbpfProbe;
pub use types::SynRawData;

#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    #[error("failed to load BPF object: {0}")]
    Load(#[from] aya::EbpfError),

    #[error("XDP program 'huginn_xdp_syn' not found in BPF object")]
    ProgramNotFound,

    #[error("BPF program is not an XDP program: {0}")]
    ProgramType(#[source] aya::programs::ProgramError),

    #[error("failed to load XDP program into kernel: {0}")]
    ProgramLoad(#[source] aya::programs::ProgramError),

    #[error("failed to attach XDP program to interface: {0}")]
    Attach(#[source] aya::programs::ProgramError),
}
