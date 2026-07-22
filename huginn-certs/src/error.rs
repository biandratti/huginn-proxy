//! Error type for the certificate crate.

use thiserror::Error;

/// Errors that can occur while loading or resolving TLS certificate material.
#[derive(Debug, Error)]
pub enum CertError {
    /// A certificate or key file could not be read, parsed, or was empty/invalid.
    #[error("{0}")]
    Tls(String),
}
