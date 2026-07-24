use serde::{Deserialize, Serialize};

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
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
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
    /// Elliptic curve / key-exchange group preferences.
    ///
    /// Specifies the order of preference for the groups used in (EC)DHE key
    /// exchange; the first entry is most preferred. Valid names are those returned
    /// by `supported_curves()`.
    ///
    /// Default: empty, which keeps the provider's safe defaults — including the
    /// post-quantum hybrid `X25519MLKEM768`. Setting an explicit list applies
    /// exactly those groups, so include a PQ hybrid to retain post-quantum
    /// protection.
    #[serde(default)]
    pub curve_preferences: Vec<String>,
    /// Strict SNI checking.
    ///
    /// When `true`, a TLS connection whose SNI matches no configured domain cert is
    /// rejected (`unrecognized_name`) instead of being served the default certificate
    /// (the catch-all domain's cert).
    ///
    /// Default: false (lenient, serve the default cert for unmatched SNI).
    #[serde(default)]
    pub sni_strict: bool,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            versions: default_tls_versions(),
            min_version: default_min_version(),
            max_version: default_max_version(),
            cipher_suites: default_cipher_suites(),
            curve_preferences: Vec::new(),
            sni_strict: false,
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

/// Session resumption configuration for TLS
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct SessionResumptionConfig {
    /// Enable session resumption (default: true)
    ///
    /// When enabled, non-mTLS domains issue **stateless TLS session tickets** so
    /// clients can resume without a round-trip. mTLS domains never resume (the
    /// client certificate is re-verified on every connection). There is no
    /// server-side session cache.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for SessionResumptionConfig {
    fn default() -> Self {
        Self { enabled: default_true() }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Application-Layer Protocol Negotiation (ALPN) protocols
    /// Common values: ["h2", "http/1.1"]
    /// Default: empty (no ALPN)
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Controls TLS versions and cipher suites
    #[serde(default)]
    pub options: TlsOptions,
    /// Session resumption configuration
    #[serde(default)]
    pub session_resumption: SessionResumptionConfig,
}

/// Allowlisted effective-config view of TLS: `{"enabled": false}` when TLS is off, otherwise the
/// full view. Certificate/key material is never included. Client authentication is per-domain
/// (see the domain view's `client_auth_configured` flag), not part of the static TLS section.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum TlsView<'a> {
    Disabled { enabled: bool },
    Enabled(TlsEnabledView<'a>),
}

#[derive(Serialize)]
pub(crate) struct TlsEnabledView<'a> {
    enabled: bool,
    alpn: &'a [String],
    options: TlsOptionsView<'a>,
    session_resumption: SessionResumptionView,
}

#[derive(Serialize)]
struct TlsOptionsView<'a> {
    versions: Vec<&'static str>,
    min_version: Option<&'static str>,
    max_version: Option<&'static str>,
    cipher_suites: &'a [String],
    curve_preferences: &'a [String],
    sni_strict: bool,
}

#[derive(Serialize)]
struct SessionResumptionView {
    enabled: bool,
}

/// Build the effective-config view for the optional TLS section.
pub(crate) fn effective_tls_view(config: Option<&TlsConfig>) -> TlsView<'_> {
    let Some(config) = config else {
        return TlsView::Disabled { enabled: false };
    };

    TlsView::Enabled(TlsEnabledView {
        enabled: true,
        alpn: config.alpn.as_slice(),
        options: TlsOptionsView {
            versions: config
                .options
                .versions
                .iter()
                .map(|version| version.as_str())
                .collect(),
            min_version: config.options.min_version.map(TlsVersion::as_str),
            max_version: config.options.max_version.map(TlsVersion::as_str),
            cipher_suites: config.options.cipher_suites.as_slice(),
            curve_preferences: config.options.curve_preferences.as_slice(),
            sni_strict: config.options.sni_strict,
        },
        session_resumption: SessionResumptionView { enabled: config.session_resumption.enabled },
    })
}

impl TlsVersion {
    fn as_str(self) -> &'static str {
        match self {
            TlsVersion::V1_2 => "1.2",
            TlsVersion::V1_3 => "1.3",
        }
    }
}
