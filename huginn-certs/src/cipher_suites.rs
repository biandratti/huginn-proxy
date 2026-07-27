//! Cipher-suite name ⇄ rustls type mapping for the aws-lc-rs provider.
//!
//! The crate builds each per-SNI `ServerConfig` with an explicit
//! `CryptoProvider`; when a config declares cipher suites by name, this module
//! resolves them into the `SupportedCipherSuite` values that override the
//! provider's defaults. An **empty** list means callers keep the provider
//! defaults.
//!
//! Analogous to [`crate::kx_groups`]: [`CipherSuiteName`] is the single source of
//! truth for the wire name, the rustls mapping, and config deserialization, so an
//! unknown name is rejected at config parse time rather than silently dropped.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite as cs;
use tokio_rustls::rustls::SupportedCipherSuite;

/// A selectable cipher suite in `[tls.options].cipher_suites`.
///
/// Wire names match the rustls constant names; the enum is the typed form used
/// after parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(try_from = "String", into = "&'static str")]
pub enum CipherSuiteName {
    /// TLS 1.3, AES-128-GCM.
    Tls13Aes128GcmSha256,
    /// TLS 1.3, AES-256-GCM.
    Tls13Aes256GcmSha384,
    /// TLS 1.3, ChaCha20-Poly1305.
    Tls13Chacha20Poly1305Sha256,
    /// TLS 1.2, ECDHE-ECDSA, AES-128-GCM.
    TlsEcdheEcdsaWithAes128GcmSha256,
    /// TLS 1.2, ECDHE-ECDSA, AES-256-GCM.
    TlsEcdheEcdsaWithAes256GcmSha384,
    /// TLS 1.2, ECDHE-ECDSA, ChaCha20-Poly1305.
    TlsEcdheEcdsaWithChacha20Poly1305Sha256,
    /// TLS 1.2, ECDHE-RSA, AES-128-GCM.
    TlsEcdheRsaWithAes128GcmSha256,
    /// TLS 1.2, ECDHE-RSA, AES-256-GCM.
    TlsEcdheRsaWithAes256GcmSha384,
    /// TLS 1.2, ECDHE-RSA, ChaCha20-Poly1305.
    TlsEcdheRsaWithChacha20Poly1305Sha256,
}

impl CipherSuiteName {
    /// All selectable suites, TLS 1.3 first, then TLS 1.2 (ECDSA before RSA).
    pub const ALL: &'static [Self] = &[
        Self::Tls13Aes128GcmSha256,
        Self::Tls13Aes256GcmSha384,
        Self::Tls13Chacha20Poly1305Sha256,
        Self::TlsEcdheEcdsaWithAes128GcmSha256,
        Self::TlsEcdheEcdsaWithAes256GcmSha384,
        Self::TlsEcdheEcdsaWithChacha20Poly1305Sha256,
        Self::TlsEcdheRsaWithAes128GcmSha256,
        Self::TlsEcdheRsaWithAes256GcmSha384,
        Self::TlsEcdheRsaWithChacha20Poly1305Sha256,
    ];

    /// Config / documentation wire name (e.g. `"TLS13_AES_128_GCM_SHA256"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls13Aes128GcmSha256 => "TLS13_AES_128_GCM_SHA256",
            Self::Tls13Aes256GcmSha384 => "TLS13_AES_256_GCM_SHA384",
            Self::Tls13Chacha20Poly1305Sha256 => "TLS13_CHACHA20_POLY1305_SHA256",
            Self::TlsEcdheEcdsaWithAes128GcmSha256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            Self::TlsEcdheEcdsaWithAes256GcmSha384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            Self::TlsEcdheEcdsaWithChacha20Poly1305Sha256 => {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            Self::TlsEcdheRsaWithAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            Self::TlsEcdheRsaWithAes256GcmSha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            Self::TlsEcdheRsaWithChacha20Poly1305Sha256 => {
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            }
        }
    }

    /// The aws-lc-rs rustls cipher suite for this name.
    #[must_use]
    pub fn to_rustls(self) -> SupportedCipherSuite {
        match self {
            Self::Tls13Aes128GcmSha256 => cs::TLS13_AES_128_GCM_SHA256,
            Self::Tls13Aes256GcmSha384 => cs::TLS13_AES_256_GCM_SHA384,
            Self::Tls13Chacha20Poly1305Sha256 => cs::TLS13_CHACHA20_POLY1305_SHA256,
            Self::TlsEcdheEcdsaWithAes128GcmSha256 => cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            Self::TlsEcdheEcdsaWithAes256GcmSha384 => cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            Self::TlsEcdheEcdsaWithChacha20Poly1305Sha256 => {
                cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            Self::TlsEcdheRsaWithAes128GcmSha256 => cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Self::TlsEcdheRsaWithAes256GcmSha384 => cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            Self::TlsEcdheRsaWithChacha20Poly1305Sha256 => {
                cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
        }
    }
}

impl FromStr for CipherSuiteName {
    type Err = UnknownCipherSuite;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|suite| suite.as_str() == s)
            .ok_or_else(|| UnknownCipherSuite(s.to_owned()))
    }
}

impl std::fmt::Display for CipherSuiteName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<CipherSuiteName> for &'static str {
    fn from(name: CipherSuiteName) -> Self {
        name.as_str()
    }
}

impl TryFrom<String> for CipherSuiteName {
    type Error = UnknownCipherSuite;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// A configured cipher-suite name that no aws-lc-rs suite matches.
///
/// Surfaces as the deserialization error, so a bad `cipher_suites` entry fails at
/// config parse time with the offending value and the valid set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCipherSuite(String);

impl std::fmt::Display for UnknownCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown cipher suite `{}`; supported: {}",
            self.0,
            supported_cipher_suites().join(", ")
        )
    }
}

impl std::error::Error for UnknownCipherSuite {}

/// Wire names of all selectable cipher suites (same order as [`CipherSuiteName::ALL`]).
pub fn supported_cipher_suites() -> Vec<&'static str> {
    CipherSuiteName::ALL
        .iter()
        .map(|suite| suite.as_str())
        .collect()
}

/// Whether `name` is a selectable cipher suite with the aws-lc-rs provider.
pub fn is_cipher_suite_supported(name: &str) -> bool {
    CipherSuiteName::from_str(name).is_ok()
}

/// Resolve typed suite names into rustls `SupportedCipherSuite` values, in the
/// order given (first = most preferred).
///
/// An empty result means callers should fall back to the provider's default
/// suite list.
pub fn resolve_cipher_suites(names: &[CipherSuiteName]) -> Vec<SupportedCipherSuite> {
    names
        .iter()
        .copied()
        .map(CipherSuiteName::to_rustls)
        .collect()
}
