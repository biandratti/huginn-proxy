use serde::Deserialize;

/// TLS version configuration
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    /// TLS 1.2
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3
    #[serde(rename = "1.3")]
    V1_3,
}

/// Advanced TLS configuration options
#[derive(Debug, Deserialize, Clone)]
pub struct TlsOptions {
    /// Allowed TLS versions
    /// Options: ["1.2"], ["1.3"], or ["1.2", "1.3"]
    /// Default: ["1.2", "1.3"] (all supported versions)
    #[serde(default = "default_tls_versions")]
    pub versions: Vec<TlsVersion>,
    /// Minimum TLS version
    /// Options: "1.2" or "1.3"
    /// Default: None (no minimum enforced)
    /// If specified, overrides `versions` to enforce minimum version
    #[serde(default = "default_min_version")]
    pub min_version: Option<TlsVersion>,
    /// Maximum TLS version
    /// Options: "1.2" or "1.3"
    /// Default: None (no maximum enforced)
    /// If specified, overrides `versions` to enforce maximum version
    #[serde(default = "default_max_version")]
    pub max_version: Option<TlsVersion>,
    /// Allowed cipher suites (by name)
    ///
    /// Default: uses rustls safe defaults (all supported cipher suites)
    /// See `supported_cipher_suites()` for the complete list.

    #[serde(default = "default_cipher_suites")]
    pub cipher_suites: Vec<String>,
    /// Elliptic curve preferences (key exchange groups)
    ///
    /// Specifies the order of preference for elliptic curves used in ECDHE key exchange.
    /// The first curve in the list is preferred.
    ///
    /// Default: empty (uses rustls safe defaults)
    #[serde(default = "default_curve_preferences")]
    pub curve_preferences: Vec<String>,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            versions: default_tls_versions(),
            min_version: default_min_version(),
            max_version: default_max_version(),
            cipher_suites: default_cipher_suites(),
            curve_preferences: default_curve_preferences(),
        }
    }
}

fn default_tls_versions() -> Vec<TlsVersion> {
    vec![TlsVersion::V1_2, TlsVersion::V1_3]
}

fn default_min_version() -> Option<TlsVersion> {
    None
}

fn default_max_version() -> Option<TlsVersion> {
    None
}

fn default_cipher_suites() -> Vec<String> {
    crate::tls::cipher_suites::supported_cipher_suites()
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_curve_preferences() -> Vec<String> {
    crate::tls::curves::supported_curves()
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}

/// Client authentication mode for mTLS
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    /// Client authentication is disabled (default)
    #[default]
    Disabled,
    /// Client authentication is required
    /// Clients must present valid certificates signed by the specified CA
    Required {
        /// Path to client CA certificate file (PEM format)
        /// File must exist and be readable at startup
        /// Can contain one or more CA certificates
        ca_cert_path: String,
    },
}

/// Session resumption configuration for TLS
#[derive(Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct SessionResumptionConfig {
    /// Enable session resumption (default: true)
    /// When enabled, clients can reuse previous TLS sessions to reduce handshake overhead
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of sessions to cache (default: 256)
    /// Only applies to TLS 1.2 session ID resumption
    /// TLS 1.3 uses stateless session tickets and doesn't use this cache
    #[serde(default = "default_session_cache_size")]
    pub max_sessions: usize,
}

impl Default for SessionResumptionConfig {
    fn default() -> Self {
        Self { enabled: default_true(), max_sessions: default_session_cache_size() }
    }
}

fn default_true() -> bool {
    true
}

fn default_session_cache_size() -> usize {
    256
}

/// TLS termination configuration
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    /// Path to TLS certificate file (PEM format)
    /// File must exist and be readable at startup
    pub cert_path: String,
    /// Path to TLS private key file (PEM format)
    /// File must exist and be readable at startup
    pub key_path: String,
    /// Application-Layer Protocol Negotiation (ALPN) protocols
    /// Common values: ["h2", "http/1.1"]
    /// Default: empty (no ALPN)
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Certificate watch delay in seconds for hot reload
    #[serde(default = "default_cert_watch_delay_secs")]
    pub watch_delay_secs: u32,
    /// Controls TLS versions and cipher suites
    #[serde(default)]
    pub options: TlsOptions,
    /// Client authentication mode for mTLS (mutual TLS authentication)
    /// Default: disabled (no client authentication required)
    #[serde(default)]
    pub client_auth: ClientAuth,
    /// Session resumption configuration
    #[serde(default)]
    pub session_resumption: SessionResumptionConfig,
}

fn default_cert_watch_delay_secs() -> u32 {
    60
}
