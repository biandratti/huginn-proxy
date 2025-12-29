use thiserror::Error;

/// Errors that can occur in the proxy (system-level errors)
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("No private key found in key file")]
    NoPrivateKey,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("No backends configured")]
    NoBackends,

    // HTTP body/response building errors (system-level, not forwarding)
    #[error("HTTP error: {0}")]
    Http(String),
}

pub type ProxyResult<T> = std::result::Result<T, ProxyError>;
pub type Result<T> = ProxyResult<T>;
