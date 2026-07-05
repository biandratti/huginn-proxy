//! Shared constants for the ACME adapter, mirroring `rpxy-acme/src/constants.rs`.

/// Subdirectory under the cache root where ACME account keys are stored.
/// Shared across all domains managed by the same cache root (one ACME account,
/// many per-domain certificates).
pub(crate) const ACME_ACCOUNT_SUBDIR: &str = "accounts";

/// Let's Encrypt production directory URL. Re-exposed from `rustls-acme` so the
/// rest of the crate references a single crate-local constant.
pub const LETS_ENCRYPT_PRODUCTION: &str = rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY;

/// Let's Encrypt staging directory URL (higher rate limits, untrusted certs).
pub const LETS_ENCRYPT_STAGING: &str = rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY;
