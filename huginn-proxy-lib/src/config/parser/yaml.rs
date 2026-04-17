use super::ConfigParser;
use crate::config::Config;
use crate::error::{ProxyError, Result};

pub struct YamlParser;

impl ConfigParser for YamlParser {
    fn parse(&self, content: &str) -> Result<Config> {
        serde_yml::from_str(content)
            .map_err(|e| ProxyError::Config(format!("YAML parse error: {e}")))
    }

    fn format_name(&self) -> &'static str {
        "YAML"
    }
}
