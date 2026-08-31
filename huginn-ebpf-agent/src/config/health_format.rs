use super::ConfigError;

/// Wire format of `/health`, `/ready`, `/live`, and observability 404/500. `/metrics` is unchanged.
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
    let Some(raw) = get_var("HUGINN_EBPF_HEALTH_FORMAT") else {
        return Ok(HealthFormat::Json);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "json" => Ok(HealthFormat::Json),
        "text" => Ok(HealthFormat::Text),
        _ => Err(ConfigError::Invalid {
            name: "HUGINN_EBPF_HEALTH_FORMAT".to_string(),
            value: raw,
            reason: "must be json or text".to_string(),
        }),
    }
}
