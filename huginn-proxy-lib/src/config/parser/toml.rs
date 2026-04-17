use super::ConfigParser;
use crate::config::Config;
use crate::error::{ProxyError, Result};

pub struct TomlParser;

impl ConfigParser for TomlParser {
    fn parse(&self, content: &str) -> Result<Config> {
        toml::from_str(content).map_err(|e| ProxyError::Config(format!("TOML parse error: {e}")))
    }

    fn format_name(&self) -> &'static str {
        "TOML"
    }
}
