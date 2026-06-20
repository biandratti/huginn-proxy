//! Agent-wide error type.

/// Errors produced by the eBPF agent: config parsing, eBPF program loading/pinning,
/// metrics setup, and the observability HTTP server.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),

    #[error("eBPF error: {0}")]
    Ebpf(#[from] huginn_ebpf::EbpfError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("metrics error: {0}")]
    Metrics(String),

    #[error("HTTP error: {0}")]
    Http(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;
