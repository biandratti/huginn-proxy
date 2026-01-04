/// Cipher suites supported by rustls
///
/// This module provides the list of cipher suites supported by rustls.
/// rustls only supports secure cipher suites by default.
/// List of cipher suites supported by rustls
///
/// Returns a list of all cipher suite names supported by rustls.
/// These are the names that can be used in the TLS configuration.
pub fn supported_cipher_suites() -> Vec<&'static str> {
    vec![
        // TLS 1.3 cipher suites
        "TLS13_AES_128_GCM_SHA256",
        "TLS13_AES_256_GCM_SHA384",
        "TLS13_CHACHA20_POLY1305_SHA256",
        // TLS 1.2 cipher suites
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ]
}

/// Check if a cipher suite name is supported by rustls
pub fn is_cipher_suite_supported(name: &str) -> bool {
    supported_cipher_suites().contains(&name)
}
