use std::sync::Arc;

use arc_swap::ArcSwap;
use huginn_certs::cipher_suites::{is_cipher_suite_supported, supported_cipher_suites};
use huginn_certs::{ServerCryptoMap, TlsBuildOptions};
use tokio_rustls::rustls::version::{TLS12, TLS13};
use tokio_rustls::rustls::SupportedProtocolVersion;

use crate::config::{TlsConfig, TlsOptions, TlsVersion};
use crate::error::{ProxyError, Result};

/// Hot-swappable per-SNI TLS config map.
///
/// Unlike the old single [`tokio_rustls::TlsAcceptor`], the map is genuinely
/// swapped on hot-reload: certificate rotation rebuilds the [`ServerCryptoMap`]
/// and stores the new pointer, while the shared stateless session ticketer lives
/// in [`huginn_certs`] and survives the swap so outstanding tickets stay valid.
pub type SharedServerCrypto = Arc<ArcSwap<ServerCryptoMap>>;

/// Project the proxy's static `TlsConfig` onto the config-agnostic
/// [`TlsBuildOptions`] consumed by [`huginn_certs::build_server_crypto`].
///
/// Carries the listener-global knobs that are actually applied per config: ALPN,
/// cipher-suite overrides, key-exchange curve overrides, resolved protocol
/// versions, resumption on/off, and `sni_strict`. An empty `curve_preferences`
/// keeps the provider's safe defaults (which include the post-quantum hybrid
/// group); a non-empty list applies exactly those groups.
pub fn tls_build_options(tls: &TlsConfig) -> TlsBuildOptions {
    TlsBuildOptions {
        alpn: tls.alpn.clone(),
        cipher_suites: tls.options.cipher_suites.clone(),
        curve_preferences: tls.options.curve_preferences.clone(),
        protocol_versions: resolve_protocol_versions(&tls.options),
        resumption_enabled: tls.session_resumption.enabled,
        sni_strict: tls.options.sni_strict,
    }
}

/// Resolve the effective TLS protocol versions to enforce from `min_version` /
/// `max_version` (which take precedence) or the `versions` list.
///
/// Returns an empty vec when no real restriction applies (both versions allowed,
/// or a degenerate empty `versions` with no bounds) so the build falls back to
/// rustls' safe defaults; a single allowed version yields a one-element list.
/// [`validate_tls_options`] guarantees `versions` and `min/max_version` are not
/// combined and that `min <= max`.
fn resolve_protocol_versions(options: &TlsOptions) -> Vec<&'static SupportedProtocolVersion> {
    let (allow_12, allow_13) = if options.min_version.is_some() || options.max_version.is_some() {
        let min = options.min_version.unwrap_or(TlsVersion::V1_2);
        let max = options.max_version.unwrap_or(TlsVersion::V1_3);
        (min == TlsVersion::V1_2, max == TlsVersion::V1_3)
    } else {
        (
            options.versions.contains(&TlsVersion::V1_2),
            options.versions.contains(&TlsVersion::V1_3),
        )
    };

    match (allow_12, allow_13) {
        (true, true) | (false, false) => Vec::new(),
        (true, false) => vec![&TLS12],
        (false, true) => vec![&TLS13],
    }
}

/// Validate static TLS options at startup (version bounds, cipher-suite and curve
/// names). Applied once before the initial [`ServerCryptoMap`] is built; these are
/// static settings that cannot change on hot-reload.
pub fn validate_tls_options(options: &TlsOptions) -> Result<()> {
    if let (Some(min), Some(max)) = (options.min_version, options.max_version) {
        if matches!((min, max), (TlsVersion::V1_3, TlsVersion::V1_2)) {
            return Err(ProxyError::Tls(
                "min_version (1.3) cannot be greater than max_version (1.2)".to_string(),
            ));
        }
    }

    if !options.versions.is_empty()
        && (options.min_version.is_some() || options.max_version.is_some())
    {
        return Err(ProxyError::Tls(
            "Cannot specify both 'versions' and 'min_version'/'max_version'. \
            Use either 'versions' or 'min_version'/'max_version'."
                .to_string(),
        ));
    }

    for suite_name in &options.cipher_suites {
        if suite_name.is_empty() {
            return Err(ProxyError::Tls("Cipher suite name cannot be empty".to_string()));
        }
        if !is_cipher_suite_supported(suite_name) {
            return Err(ProxyError::Tls(format!(
                "Cipher suite '{}' is not supported by rustls. \
                Supported cipher suites: {}",
                suite_name,
                supported_cipher_suites().join(", ")
            )));
        }
    }

    Ok(())
}
