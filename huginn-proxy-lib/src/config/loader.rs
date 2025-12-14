use std::{fs, path::Path};

use crate::config::types::Config;
use crate::config::validator;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error while reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse config TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

pub fn load_from_path(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    if let Err(err) = validator::validate(&config) {
        return Err(ConfigError::Invalid(err));
    }
    Ok(config)
}
