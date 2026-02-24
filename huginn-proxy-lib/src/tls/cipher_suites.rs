use tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite as cs;
use tokio_rustls::rustls::SupportedCipherSuite;
use tracing::warn;

/// Cipher suites supported by rustls with the aws-lc-rs crypto provider.
pub fn supported_cipher_suites() -> Vec<&'static str> {
    vec![
        // TLS 1.3
        "TLS13_AES_128_GCM_SHA256",
        "TLS13_AES_256_GCM_SHA384",
        "TLS13_CHACHA20_POLY1305_SHA256",
        // TLS 1.2 — ECDSA
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        // TLS 1.2 — RSA
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ]
}

/// Check if a cipher suite name is supported by rustls.
pub fn is_cipher_suite_supported(name: &str) -> bool {
    supported_cipher_suites().contains(&name)
}

/// Resolve a list of cipher suite name strings into `SupportedCipherSuite` values.
///
/// Unknown names are silently skipped (validation should have been done earlier
/// by [`is_cipher_suite_supported`]). If the returned `Vec` is empty, callers
/// should fall back to the provider's default suite list.
pub fn resolve_cipher_suites(names: &[String]) -> Vec<SupportedCipherSuite> {
    names
        .iter()
        .filter_map(|name| match name.as_str() {
            "TLS13_AES_128_GCM_SHA256" => Some(cs::TLS13_AES_128_GCM_SHA256),
            "TLS13_AES_256_GCM_SHA384" => Some(cs::TLS13_AES_256_GCM_SHA384),
            "TLS13_CHACHA20_POLY1305_SHA256" => Some(cs::TLS13_CHACHA20_POLY1305_SHA256),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                Some(cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            }
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                Some(cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            }
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                Some(cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
            }
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                Some(cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            }
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                Some(cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
            }
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                Some(cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
            }
            unknown => {
                warn!(cipher_suite = unknown, "unknown cipher suite ignored; check `supported_cipher_suites()` for valid names");
                None
            }
        })
        .collect()
}
