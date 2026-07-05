use serde::Deserialize;

/// Static ACME configuration (the `[acme]` block).
///
/// ACME drives an account and background issuance/renewal tasks, so it is part of
/// [`crate::config::StaticConfig`] and requires a restart to change. Presence of this
/// block is required by any domain that resolves to ACME: either an explicit
/// `cert = { type = "acme" }` or an omitted `cert` (ACME-by-default), validated in
/// `config/loader.rs`.
///
/// Only exact hosts are supported (no wildcards, no catch-all); wildcards are delegated
/// to an external issuer (cert-manager / Caddy / lego) consumed via `cert = { type = "file" }`.
/// EAB (External Account Binding) is not supported by the underlying `rustls-acme`, so CAs
/// that require it (ZeroSSL, Google Public CA, Sectigo, …) must be used via a file cert.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct AcmeConfig {
    /// Contact email registered with the ACME account (sent as `mailto:` contact).
    pub contact_email: String,
    /// Use the Let's Encrypt staging directory instead of production.
    ///
    /// Ignored when `directory_url` is set. Default: `false` (production).
    #[serde(default)]
    pub staging: bool,
    /// Override the ACME directory URL (e.g. a private CA or Pebble for tests).
    ///
    /// When set, takes precedence over `staging`. Default: `None`.
    #[serde(default)]
    pub directory_url: Option<String>,
    /// PEM bundle to trust for the ACME **directory** TLS connection instead of the compiled-in
    /// public (webpki) roots.
    ///
    /// Needed only for private/test ACME servers (e.g. Pebble) whose directory is served with a
    /// self-signed CA. Leave unset for public CAs like Let's Encrypt. Default: `None`.
    #[serde(default)]
    pub directory_ca_path: Option<String>,
    /// Filesystem directory for the ACME cache (account key + issued certificates).
    ///
    /// Backed by `rustls_acme::caches::DirCache`. Must be writable and persistent
    /// across restarts to avoid re-issuing certificates on every boot.
    pub cache_dir: String,
}
