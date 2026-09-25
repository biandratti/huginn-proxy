use super::{ConfigError, env};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HealthFormat {
    #[default]
    Json,
    Text,
}

impl HealthFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
        }
    }
}

pub(super) fn parse_health_format(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<HealthFormat, ConfigError> {
    let Some(raw) = get_var(env::HEALTH_FORMAT) else {
        return Ok(HealthFormat::Json);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "json" => Ok(HealthFormat::Json),
        "text" => Ok(HealthFormat::Text),
        _ => Err(ConfigError::invalid(env::HEALTH_FORMAT, raw, "must be json or text")),
    }
}
