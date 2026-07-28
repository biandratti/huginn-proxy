use huginn_certs::{CipherSuiteName, KxGroupName};
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
    /// Allowed TLS versions.
    ///
    /// Options: `["1.2"]`, `["1.3"]`, or `["1.2", "1.3"]`.
    ///
    /// Default: empty, meaning no restriction (both versions). Empty is what makes
    /// "unset" distinguishable from an explicit list, so `min_version` /
    /// `max_version` can be used on their own; the two forms are mutually exclusive.
    #[serde(default)]
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
    /// Allowed cipher suites, in order of preference.
    ///
    /// Valid names are those returned by `supported_cipher_suites()` /
    /// [`CipherSuiteName`]; unknown names fail at config parse time.
    ///
    /// Default: all supported suites.
    #[serde(default = "default_cipher_suites")]
    pub cipher_suites: Vec<CipherSuiteName>,
    /// Elliptic curve / key-exchange group preferences.
    ///
    /// Specifies the order of preference for the groups used in (EC)DHE key
    /// exchange; the first entry is most preferred. Valid names are those returned
    /// by `supported_curves()` / [`KxGroupName`].
    ///
    /// Default: empty, which keeps the provider's safe defaults, including the
    /// post-quantum hybrid `X25519MLKEM768`. Setting an explicit list applies
    /// exactly those groups, so include a PQ hybrid to retain post-quantum
    /// protection. Unknown names fail at config parse time.
    #[serde(default)]
    pub curve_preferences: Vec<KxGroupName>,
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

impl TlsOptions {
    /// Reject contradictory version settings.
    pub fn validate(&self) -> crate::error::Result<()> {
        if matches!(
            (self.min_version, self.max_version),
            (Some(TlsVersion::V1_3), Some(TlsVersion::V1_2))
        ) {
            return Err(crate::error::ProxyError::Tls(
                "min_version (1.3) cannot be greater than max_version (1.2)".to_string(),
            ));
        }

        if !self.versions.is_empty() && (self.min_version.is_some() || self.max_version.is_some()) {
            return Err(crate::error::ProxyError::Tls(
                "Cannot specify both 'versions' and 'min_version'/'max_version'. \
                Use either 'versions' or 'min_version'/'max_version'."
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// The TLS versions the handshake will actually accept, in ascending order.
    ///
    /// `min_version` / `max_version` take precedence over `versions`, and an unset
    /// `versions` means both. Empty only for the contradictory `min > max`, which
    /// [`crate::config::Config::validate_cross_refs`] rejects before it reaches here.
    pub fn resolved_versions(&self) -> Vec<TlsVersion> {
        let (v1_2, v1_3) = if self.min_version.is_some() || self.max_version.is_some() {
            let min = self.min_version.unwrap_or(TlsVersion::V1_2);
            let max = self.max_version.unwrap_or(TlsVersion::V1_3);
            (min == TlsVersion::V1_2, max == TlsVersion::V1_3)
        } else if self.versions.is_empty() {
            (true, true)
        } else {
            (
                self.versions.contains(&TlsVersion::V1_2),
                self.versions.contains(&TlsVersion::V1_3),
            )
        };

        let mut resolved = Vec::with_capacity(2);
        if v1_2 {
            resolved.push(TlsVersion::V1_2);
        }
        if v1_3 {
            resolved.push(TlsVersion::V1_3);
        }
        resolved
    }
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            versions: Vec::new(),
            min_version: default_min_version(),
            max_version: default_max_version(),
            cipher_suites: default_cipher_suites(),
            curve_preferences: Vec::new(),
            sni_strict: false,
        }
    }
}

fn default_min_version() -> Option<TlsVersion> {
    None
}

fn default_max_version() -> Option<TlsVersion> {
    None
}

fn default_cipher_suites() -> Vec<CipherSuiteName> {
    CipherSuiteName::ALL.to_vec()
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
    cipher_suites: &'a [CipherSuiteName],
    curve_preferences: &'a [KxGroupName],
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
                .resolved_versions()
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
