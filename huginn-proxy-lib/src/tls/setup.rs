use std::sync::Arc;

use arc_swap::ArcSwap;
use huginn_certs::{ServerCryptoMap, TlsBuildOptions};

use crate::config::{TlsConfig, TlsOptions, TlsVersion};
use crate::error::{ProxyError, Result};
use crate::tls::cipher_suites::{is_cipher_suite_supported, supported_cipher_suites};
use crate::tls::curves::{is_curve_supported, supported_curves};

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
/// Only the listener-global knobs that are actually applied per config are
/// carried: ALPN, cipher-suite overrides, resumption on/off, and `sni_strict`.
/// TLS versions and key-exchange curves are intentionally left at the provider's
/// safe defaults (matching rpxy), so `min/max_version` and `curve_preferences`
/// are validated (see [`validate_tls_options`]) but not applied.
pub fn tls_build_options(tls: &TlsConfig) -> TlsBuildOptions {
    TlsBuildOptions {
        alpn: tls.alpn.clone(),
        cipher_suites: tls.options.cipher_suites.clone(),
        resumption_enabled: tls.session_resumption.enabled,
        sni_strict: tls.options.sni_strict,
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

    for curve_name in &options.curve_preferences {
        if curve_name.is_empty() {
            return Err(ProxyError::Tls("Curve name cannot be empty".to_string()));
        }
        if !is_curve_supported(curve_name) {
            return Err(ProxyError::Tls(format!(
                "Curve '{}' is not supported by rustls. \
                Supported curves: {}",
                curve_name,
                supported_curves().join(", ")
            )));
        }
    }

    Ok(())
}
