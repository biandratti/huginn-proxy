use super::ConfigError;
use huginn_ebpf::EbpfLogLevel;

pub(super) fn resolve_log_level(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<EbpfLogLevel, ConfigError> {
    let Some(raw) = get_var("HUGINN_EBPF_LOG_LEVEL") else {
        return Ok(EbpfLogLevel::Off);
    };
    EbpfLogLevel::parse(&raw).ok_or_else(|| ConfigError::Invalid {
        name: "HUGINN_EBPF_LOG_LEVEL".to_string(),
        value: raw,
        reason: "must be one of: off, error, warn, info, debug, trace (case-insensitive)"
            .to_string(),
    })
}
