use serde::{Deserialize, Serialize};

/// Custom header configuration
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct CustomHeader {
    /// Header name (e.g., "X-Frame-Options")
    pub name: String,
    /// Header value (e.g., "DENY")
    pub value: String,
}

/// Header manipulation for requests or responses
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
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
pub struct HeaderManipulation {
    /// Request header manipulation
    #[serde(default)]
    pub request: HeaderManipulationGroup,
    /// Response header manipulation
    #[serde(default)]
    pub response: HeaderManipulationGroup,
}
