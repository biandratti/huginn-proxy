//! Error type for the ACME adapter, mirroring `rpxy-acme/src/error.rs`.

/// Errors returned while wiring up ACME.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// `start_acme` was called with no domains; the caller should pass `None` instead.
    #[error("no ACME domains provided")]
    NoDomains,
    /// The directory CA bundle could not be read from disk.
    #[error("failed to read ACME directory CA bundle '{path}': {source}")]
    DirectoryCaRead {
        /// Path that failed to read.
        path: String,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// The directory CA bundle could not be parsed as PEM certificates.
    #[error("failed to parse ACME directory CA bundle '{path}': {source}")]
    DirectoryCaParse {
        /// Path that failed to parse.
        path: String,
        /// Underlying PEM parse error.
        source: rustls_pki_types::pem::Error,
    },
    /// The directory CA bundle parsed but contained no certificates.
    #[error("ACME directory CA bundle '{path}' contained no certificates")]
    DirectoryCaEmpty {
        /// Path that contained no certificates.
        path: String,
    },
    /// Building the rustls client config for the ACME directory failed.
    #[error("failed to build ACME directory TLS config: {0}")]
    DirectoryTls(#[from] rustls_acme::rustls::Error),
    /// Building the platform certificate verifier (system trust store) for the ACME
    /// directory connection failed. Container images must ship a system CA bundle
    /// (e.g. `ca-certificates`) for the default (non-custom-CA) path to work.
    #[error("failed to build platform certificate verifier for ACME directory: {0}")]
    DirectoryVerifier(rustls_acme::rustls::Error),
    /// The ACME cache directory is not writable. Without write access the proxy would
    /// obtain a certificate from the CA and then silently fail to persist it, burning
    /// rate-limit quota on every restart.
    #[error("ACME cache directory not writable for domain '{domain}' at '{path}': {source}")]
    CacheNotWritable {
        /// Domain whose cache directory failed the write check.
        domain: String,
        /// Cache directory path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}
