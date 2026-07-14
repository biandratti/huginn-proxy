use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Placeholder emitted whenever a [`Secret`] is serialized.
pub const REDACTED: &str = "<redacted>";

/// A configuration value that must never appear in serialized output.
///
/// `Secret<T>` deserializes and compares transparently, but its [`Serialize`] implementation
/// always emits the `<redacted>` placeholder instead of the wrapped value. This makes redaction a
/// property of the type: any value that flows into a serialized surface (the effective-config view,
/// structured logs) is masked by construction, and reading the real value requires an explicit
/// [`expose`](Self::expose) call at the use site.
///
/// `Debug` is intentionally *transparent* (delegates to the inner value). Debug output is only used
/// internally (e.g. the `huginn_config_hash` fingerprint) and is never emitted to a user-facing
/// surface, so masking it would silently stop that fingerprint from reflecting secret changes
/// without adding any confidentiality.
#[derive(Clone, Default)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the underlying value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Secret)
    }
}

impl<T: fmt::Debug> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: PartialEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Eq> Eq for Secret<T> {}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}
