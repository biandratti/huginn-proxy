use super::{ConfigError, env};
use huginn_ebpf::{CaptureBackend, XdpAttachMode};

/// Resolve `HUGINN_EBPF_CAPTURE` (`xdp-native` | `xdp-skb` | `tc`). Default: `xdp-native`.
///
/// On VLAN/bond edges prefer `tc`: generic XDP drops GRO-merged packets; TC never drops.
pub fn resolve_capture_backend(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<CaptureBackend, ConfigError> {
    let Some(raw) = get_var(env::CAPTURE) else {
        return Ok(CaptureBackend::Xdp(XdpAttachMode::Native));
    };

    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "xdp-native" => Ok(CaptureBackend::Xdp(XdpAttachMode::Native)),
        "xdp-skb" => Ok(CaptureBackend::Xdp(XdpAttachMode::Skb)),
        "tc" => Ok(CaptureBackend::Tc),
        _ => Err(ConfigError::invalid(
            env::CAPTURE,
            raw,
            "must be 'xdp-native', 'xdp-skb', or 'tc' (case-insensitive)",
        )),
    }
}
