// eBPF/XDP is Linux-only. This crate does not compile for other targets.
#![cfg(target_os = "linux")]
// Unsafe is required in one narrow, documented site:
//   - types.rs: unsafe impl aya::Pod for SynRawData (kernel memory safety guarantee)
// All other unsafe is denied.
#![deny(unsafe_code)]

pub mod probe;
pub mod types;

pub mod pin;
pub use probe::{syn_insert_failures_count_from_path, EbpfProbe};
pub use types::{parse_syn, quirk_bits, SynRawData};

/// For dev/diagnostics only (e.g. workspace example that loads the ELF and checks maps).
/// Returns the compiled XDP BPF object bytes.
#[doc(hidden)]
pub fn bpf_object_bytes() -> &'static [u8] {
    probe::bpf_object_bytes()
}

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
