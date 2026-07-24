//! Key-exchange groups (elliptic curves) supported for the aws-lc-rs provider.
//!
//! These are the curve names accepted in `[tls.options].curve_preferences` and
//! resolved into rustls key-exchange groups by
//! [`huginn_certs::kx_groups::resolve_kx_groups`]. Only groups the aws-lc-rs
//! provider actually offers are listed; the list here and the resolver there must
//! stay in sync.
//!
//! An empty `curve_preferences` keeps the provider defaults, which already lead
//! with the post-quantum hybrid `X25519MLKEM768`.

/// Curve / key-exchange group names supported with the aws-lc-rs provider, in a
/// sensible preference order (post-quantum hybrids first).
///
/// - `X25519MLKEM768` - post-quantum hybrid (X25519 + ML-KEM-768)
/// - `SECP256R1MLKEM768` - post-quantum hybrid (P-256 + ML-KEM-768)
/// - `X25519` - Curve25519, fast and widely supported
/// - `secp256r1` - NIST P-256
/// - `secp384r1` - NIST P-384
///
/// Note: `secp521r1` (P-521) is intentionally absent — the aws-lc-rs provider
/// does not expose it as a key-exchange group.
pub fn supported_curves() -> Vec<&'static str> {
    vec!["X25519MLKEM768", "SECP256R1MLKEM768", "X25519", "secp256r1", "secp384r1"]
}

/// Check if a curve name is supported by the aws-lc-rs provider.
pub fn is_curve_supported(name: &str) -> bool {
    supported_curves().contains(&name)
}
