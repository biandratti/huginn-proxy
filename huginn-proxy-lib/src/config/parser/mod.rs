//! Config file parsers.
//!
//! Provides a uniform interface for loading [`Config`] from different file formats.
//! The format is detected from the file extension; TOML is used as the default.
//!
//! # Supported formats
//!
//! | Extension       | Format |
//! |-----------------|--------|
//! | `.toml`         | TOML   |
//! | `.yaml`, `.yml` | YAML   |
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use huginn_proxy_lib::config::parser::ConfigFormat;
//!
//! let fmt = ConfigFormat::from_path(Path::new("config.yaml"));
//! let cfg = fmt.parser().parse(r#"
//! backends:
//!   - address: "localhost:3000"
//! routes:
//!   - prefix: "/"
//!     backend: "localhost:3000"
//! "#).unwrap();
//! ```

mod toml;
mod yaml;

pub use toml::TomlParser;
pub use yaml::YamlParser;

use std::fmt;
use std::path::Path;

use crate::config::Config;
use crate::error::Result;

/// Trait implemented by every config file parser.
///
/// Parsers are stateless — a single instance can be reused across reloads.
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
    /// TOML — default for `.toml` files and any unknown extension.
    Toml,
    /// YAML — used for `.yaml` and `.yml` files.
    Yaml,
}

impl ConfigFormat {
    /// Detect the format from a file path's extension.
    ///
    /// Falls back to [`ConfigFormat::Toml`] for unknown or missing extensions.
    pub fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => Self::Yaml,
            _ => Self::Toml,
        }
    }

    /// Return the parser for this format.
    ///
    /// The returned reference is to a static instance — no allocation.
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
