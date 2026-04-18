//! Config file parsers.
//!
//! Provides a uniform interface for loading [`Config`] from different file formats.
//! The format is detected from the file extension; an unrecognised or missing extension
//! is an error.
//!
//! # Supported formats
//!
//! | Extension       | Format |
//! |-----------------|--------|
//! | `.toml`         | TOML   |
//! | `.yaml`, `.yml` | YAML   |

mod toml;
mod yaml;

pub use toml::TomlParser;
pub use yaml::YamlParser;

use std::fmt;
use std::path::Path;

use crate::config::Config;
use crate::error::Result;

/// Trait implemented by every config file parser
pub trait ConfigParser: Send + Sync {
    /// Parse `content` into a [`Config`].
    ///
    /// Returns a [`crate::error::ProxyError::Config`] on any syntax or
    /// semantic parse error. Cross-reference validation (e.g. route → backend)
    /// is performed by the caller after this returns.
    fn parse(&self, content: &str) -> Result<Config>;

    /// Human-readable format name, used in error messages.
    fn format_name(&self) -> &'static str;
}

/// Detected config file format.
///
/// Use [`ConfigFormat::from_path`] to detect from a file extension, then call
/// [`ConfigFormat::parser`] to obtain the matching [`ConfigParser`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// TOML — used for `.toml` files.
    Toml,
    /// YAML — used for `.yaml` and `.yml` files.
    Yaml,
}

impl ConfigFormat {
    /// Detect the format from a file path's extension.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ProxyError::Config`] if the extension is missing or not one of
    /// `.toml`, `.yaml`, `.yml`.
    pub fn from_path(path: &Path) -> Result<Self> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("toml") => Ok(Self::Toml),
            Some("yaml") | Some("yml") => Ok(Self::Yaml),
            Some(ext) => Err(crate::error::ProxyError::Config(format!(
                "Unsupported config file extension '.{ext}'. Use .toml, .yaml, or .yml"
            ))),
            None => Err(crate::error::ProxyError::Config(format!(
                "Config file '{}' has no extension. Use .toml, .yaml, or .yml",
                path.display()
            ))),
        }
    }

    /// Return the parser for this format.
    pub fn parser(self) -> &'static dyn ConfigParser {
        match self {
            Self::Toml => &TomlParser,
            Self::Yaml => &YamlParser,
        }
    }
}

impl fmt::Display for ConfigFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml => write!(f, "TOML"),
            Self::Yaml => write!(f, "YAML"),
        }
    }
}
