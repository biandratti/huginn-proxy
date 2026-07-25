//! Key-exchange group (elliptic curve) name ⇄ rustls type mapping for the
//! aws-lc-rs provider.
//!
//! Analogous to [`crate::cipher_suites`]: when a config declares curve
//! preferences by name, this resolves them into the `SupportedKxGroup` values
//! that override the provider's default key-exchange groups. An **empty** list
//! means callers keep the provider defaults — which include the post-quantum
//! hybrid group `X25519MLKEM768`. Unknown names are validated away by the config
//! layer before they reach here.
//!
//! Only groups the aws-lc-rs provider actually offers are mappable. Notably
//! `secp521r1` is **not** available as a key-exchange group and is therefore not
//! listed here. [`supported_curves`] is the validation-side twin of
//! [`resolve_kx_groups`]; both live here so the accepted names and the resolver
//! cannot drift apart.

use tokio_rustls::rustls::crypto::aws_lc_rs::kx_group;
use tokio_rustls::rustls::crypto::SupportedKxGroup;
use tracing::warn;

/// Curve / key-exchange group names selectable in `curve_preferences`, in a
/// sensible preference order (post-quantum hybrids first).
///
/// - `X25519MLKEM768` - post-quantum hybrid (X25519 + ML-KEM-768)
/// - `SECP256R1MLKEM768` - post-quantum hybrid (P-256 + ML-KEM-768)
/// - `X25519` - Curve25519, fast and widely supported
/// - `secp256r1` - NIST P-256
/// - `secp384r1` - NIST P-384
///
/// This list and [`resolve_kx_groups`] must stay in sync. `secp521r1` (P-521) is
/// intentionally absent: the aws-lc-rs provider does not expose it as a
/// key-exchange group.
pub fn supported_curves() -> Vec<&'static str> {
    vec!["X25519MLKEM768", "SECP256R1MLKEM768", "X25519", "secp256r1", "secp384r1"]
}

/// Check whether a curve name is selectable with the aws-lc-rs provider.
pub fn is_curve_supported(name: &str) -> bool {
    supported_curves().contains(&name)
}

/// Resolve curve / key-exchange group names into `SupportedKxGroup` values, in
/// the order given (first = most preferred).
///
/// Unknown names are skipped with a warning (validation should have happened
/// earlier via the proxy's `is_curve_supported`). An empty result means callers
/// should fall back to the provider's default key-exchange groups.
pub fn resolve_kx_groups(names: &[String]) -> Vec<&'static dyn SupportedKxGroup> {
    names
        .iter()
        .filter_map(|name| match name.as_str() {
            // Post-quantum hybrids (classical + ML-KEM-768).
            "X25519MLKEM768" => Some(kx_group::X25519MLKEM768),
            "SECP256R1MLKEM768" => Some(kx_group::SECP256R1MLKEM768),
            // Classical groups.
            "X25519" => Some(kx_group::X25519),
            "secp256r1" => Some(kx_group::SECP256R1),
            "secp384r1" => Some(kx_group::SECP384R1),
            unknown => {
                warn!(
                    curve = unknown,
                    "unknown key-exchange group ignored; check the supported curve names"
                );
                None
            }
        })
        .collect()
}
