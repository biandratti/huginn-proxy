use std::sync::Arc;

use arc_swap::ArcSwap;
use huginn_certs::{ServerCryptoMap, TlsBuildOptions};
use tokio_rustls::rustls::version::{TLS12, TLS13};
use tokio_rustls::rustls::SupportedProtocolVersion;

use crate::config::{TlsConfig, TlsOptions, TlsVersion};

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

/// Map the config's effective TLS versions onto the rustls values to enforce.
///
/// An empty result means "no restriction", so the build keeps rustls' safe
/// defaults; that covers both versions being allowed (the common case) and the
/// degenerate `min > max` that `TlsOptions::validate` rejects at load anyway.
fn resolve_protocol_versions(options: &TlsOptions) -> Vec<&'static SupportedProtocolVersion> {
    let resolved = options.resolved_versions();
    match resolved.as_slice() {
        [TlsVersion::V1_2] => vec![&TLS12],
        [TlsVersion::V1_3] => vec![&TLS13],
        _ => Vec::new(),
    }
}
