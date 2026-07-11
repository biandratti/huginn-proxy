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

    #[error("failed to initialize eBPF debug logger: {0}")]
    LogInit(#[source] aya_log::Error),
}
