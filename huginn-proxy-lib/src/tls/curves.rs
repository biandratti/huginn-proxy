/// Elliptic curves (key exchange groups) supported by rustls
///
/// This module provides the list of elliptic curves supported by rustls
/// for ECDHE key exchange.
/// List of elliptic curves supported by rustls
///
/// Returns a list of all curve names supported by rustls.
/// These are the names that can be used in the TLS configuration.
///
/// rustls supports the following curves:
/// - X25519 (Curve25519) - preferred for performance
/// - secp256r1 (P-256) - widely supported
/// - secp384r1 (P-384) - higher security
/// - secp521r1 (P-521) - highest security
///
/// **Total: 4 curves**
pub fn supported_curves() -> Vec<&'static str> {
    vec![
        // X25519 (Curve25519) - preferred for performance
        "X25519",
        // NIST curves
        "secp256r1", // P-256
        "secp384r1", // P-384
        "secp521r1", // P-521
    ]
}

/// Check if a curve name is supported by rustls
pub fn is_curve_supported(name: &str) -> bool {
    supported_curves().contains(&name)
}
