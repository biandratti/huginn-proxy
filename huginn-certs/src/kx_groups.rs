//! Key-exchange group (named group) name ⇄ rustls type mapping for the
//! aws-lc-rs provider.
//!
//! Analogous to [`crate::cipher_suites`]: when a config declares
//! `curve_preferences`, this module resolves them into the `SupportedKxGroup`
//! values that override the provider's default key-exchange groups. An **empty**
//! list means callers keep the provider defaults, which include the post-quantum
//! hybrid group `X25519MLKEM768`.
//!
//! These are TLS *named groups* (not only elliptic curves): the list includes
//! post-quantum hybrids that combine a classical curve with ML-KEM. Config keeps
//! the familiar Traefik/Go name `curve_preferences`; this module uses the precise
//! rustls term.
//!
//! Only groups the aws-lc-rs provider actually offers are listed.
//! `secp521r1` is **not** available as a key-exchange group and is therefore
//! absent. [`KxGroupName`] is the single source of truth for the wire name, the
//! rustls mapping, and config deserialization.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::crypto::aws_lc_rs::kx_group;
use tokio_rustls::rustls::crypto::SupportedKxGroup;

/// A selectable key-exchange group in `[tls.options].curve_preferences`.
///
/// Wire names match the config / Traefik-style strings; the enum is the typed
/// form used after parse. Preference order for [`Self::ALL`] puts post-quantum
/// hybrids first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(try_from = "String", into = "&'static str")]
pub enum KxGroupName {
    /// Post-quantum hybrid: X25519 + ML-KEM-768.
    X25519MlKem768,
    /// Post-quantum hybrid: P-256 + ML-KEM-768.
    Secp256r1MlKem768,
    /// Curve25519.
    X25519,
    /// NIST P-256.
    Secp256r1,
    /// NIST P-384.
    Secp384r1,
}

impl KxGroupName {
    /// All selectable groups, in a sensible default preference order
    /// (post-quantum hybrids first).
    pub const ALL: &'static [Self] = &[
        Self::X25519MlKem768,
        Self::Secp256r1MlKem768,
        Self::X25519,
        Self::Secp256r1,
        Self::Secp384r1,
    ];

    /// Config / documentation wire name (e.g. `"X25519MLKEM768"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X25519MlKem768 => "X25519MLKEM768",
            Self::Secp256r1MlKem768 => "SECP256R1MLKEM768",
            Self::X25519 => "X25519",
            Self::Secp256r1 => "secp256r1",
            Self::Secp384r1 => "secp384r1",
        }
    }

    /// The aws-lc-rs rustls key-exchange group for this name.
    #[must_use]
    pub fn to_rustls(self) -> &'static dyn SupportedKxGroup {
        match self {
            Self::X25519MlKem768 => kx_group::X25519MLKEM768,
            Self::Secp256r1MlKem768 => kx_group::SECP256R1MLKEM768,
            Self::X25519 => kx_group::X25519,
            Self::Secp256r1 => kx_group::SECP256R1,
            Self::Secp384r1 => kx_group::SECP384R1,
        }
    }
}

impl FromStr for KxGroupName {
    type Err = UnknownKxGroup;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|g| g.as_str() == s)
            .ok_or_else(|| UnknownKxGroup(s.to_owned()))
    }
}

impl std::fmt::Display for KxGroupName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<KxGroupName> for &'static str {
    fn from(name: KxGroupName) -> Self {
        name.as_str()
    }
}

impl TryFrom<String> for KxGroupName {
    type Error = UnknownKxGroup;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// A configured key-exchange group name that no aws-lc-rs group matches.
///
/// Surfaces as the deserialization error, so a bad `curve_preferences` entry
/// fails at config parse time with the offending value and the valid set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKxGroup(String);

impl std::fmt::Display for UnknownKxGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown key-exchange group `{}`; supported: {}",
            self.0,
            supported_curves().join(", ")
        )
    }
}

impl std::error::Error for UnknownKxGroup {}

/// Wire names of all selectable key-exchange groups (same order as [`KxGroupName::ALL`]).
pub fn supported_curves() -> Vec<&'static str> {
    KxGroupName::ALL.iter().map(|g| g.as_str()).collect()
}

/// Whether `name` is a selectable key-exchange group with the aws-lc-rs provider.
pub fn is_curve_supported(name: &str) -> bool {
    KxGroupName::from_str(name).is_ok()
}

/// Resolve typed group names into rustls `SupportedKxGroup` values, in the order
/// given (first = most preferred).
///
/// An empty result means callers should fall back to the provider's default
/// key-exchange groups.
pub fn resolve_kx_groups(names: &[KxGroupName]) -> Vec<&'static dyn SupportedKxGroup> {
    names.iter().copied().map(KxGroupName::to_rustls).collect()
}
