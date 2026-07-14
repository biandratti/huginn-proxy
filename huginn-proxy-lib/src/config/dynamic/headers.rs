use serde::{Deserialize, Serialize};

use crate::config::Secret;

/// Custom header configuration
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CustomHeader {
    /// Header name (e.g., "X-Frame-Options")
    pub name: String,
    /// Header value (e.g., "DENY"). Redacted on serialization: header values frequently carry
    /// credentials (e.g. `Authorization`), so they are never exposed in the effective-config view
    /// or structured logs.
    pub value: Secret<String>,
}

/// Header manipulation for requests or responses
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct HeaderManipulationGroup {
    /// Headers to add (overwrite if exist)
    #[serde(default)]
    pub add: Vec<CustomHeader>,
    /// Headers to remove
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Header manipulation configuration
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct HeaderManipulation {
    /// Request header manipulation
    #[serde(default)]
    pub request: HeaderManipulationGroup,
    /// Response header manipulation
    #[serde(default)]
    pub response: HeaderManipulationGroup,
}
