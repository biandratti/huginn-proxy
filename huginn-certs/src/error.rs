//! Error type for the certificate crate.

use thiserror::Error;

/// Errors that can occur while loading or resolving TLS certificate material.
///
/// The variants distinguish the failure kinds a caller may want to treat or
/// report differently (I/O vs. parse vs. key mismatch), while staying narrower
/// than a general-purpose cert library: mTLS/client-CA and reload-service errors
/// live outside this crate.
#[derive(Debug, Error)]
pub enum CertError {
    /// A certificate or key file could not be read from disk.
    #[error("unable to load the {kind} [{path}]: {source}")]
    Io {
        /// Human-readable label of the file being read (e.g. `"certificates"`).
        kind: &'static str,
        /// Path that failed to load.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// PEM content could not be parsed.
    #[error("unable to parse the {0}")]
    Parse(String),

    /// The certificate file contained no certificates.
    #[error("no certificates found")]
    NoCertificates,

    /// No private key was found (keys must be in PKCS#8/PEM format).
    #[error("no private keys found - make sure they are in PKCS#8/PEM format")]
    NoPrivateKey,

    /// The private key could not be turned into a rustls signing key.
    #[error("failed to build signing key for '{label}': {message}")]
    SigningKey {
        /// Domain label the key belongs to.
        label: String,
        /// Underlying rustls error message.
        message: String,
    },

    /// The certificate and private key do not correspond.
    #[error("certificate and private key for '{label}' do not match: {message}")]
    KeyMismatch {
        /// Domain label whose cert/key pair is inconsistent.
        label: String,
        /// Underlying rustls error message.
        message: String,
    },
}
