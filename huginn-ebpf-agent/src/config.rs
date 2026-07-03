use huginn_ebpf::pin;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const DEFAULT_PIN_PATH: &str = pin::DEFAULT_PIN_BASE;
pub use huginn_ebpf::{CaptureBackend, XdpAttachMode};

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub dst_ip_v4: Ipv4Addr,
    pub dst_ip_v6: Ipv6Addr,
    pub dst_port: u16,
    pub pin_path: String,
    pub syn_map_max_entries: u32,
    pub capture: CaptureBackend,
    pub metrics_listen_addr: String,
    pub metrics_port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("environment variable {name} is required")]
    Missing { name: String },

    #[error("environment variable {name}: invalid value '{value}' — {reason}")]
    Invalid {
        name: String,
        value: String,
        reason: String,
    },
}

pub fn from_env(get_var: impl Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
    let interface = get_var("HUGINN_EBPF_INTERFACE")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_INTERFACE".to_string() })?;

    let dst_ip_v4_str = get_var("HUGINN_EBPF_DST_IP_V4")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_DST_IP_V4".to_string() })?;
    let dst_ip_v4: Ipv4Addr = dst_ip_v4_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_DST_IP_V4".to_string(),
        value: dst_ip_v4_str.clone(),
        reason: "must be a valid IPv4 address".to_string(),
    })?;

    let dst_ip_v6: Ipv6Addr = match get_var("HUGINN_EBPF_DST_IP_V6") {
        Some(s) => s.parse().map_err(|_| ConfigError::Invalid {
            name: "HUGINN_EBPF_DST_IP_V6".to_string(),
            value: s.clone(),
            reason: "must be a valid IPv6 address".to_string(),
        })?,
        None => Ipv6Addr::UNSPECIFIED,
    };

    let dst_port_str = get_var("HUGINN_EBPF_DST_PORT")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_DST_PORT".to_string() })?;
    let dst_port: u16 = dst_port_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_DST_PORT".to_string(),
        value: dst_port_str.clone(),
        reason: "must be a valid port number (1-65535)".to_string(),
    })?;

    let pin_path = get_var("HUGINN_EBPF_PIN_PATH").unwrap_or_else(|| DEFAULT_PIN_PATH.to_string());

    let syn_map_max_entries = get_var("HUGINN_EBPF_SYN_MAP_MAX_ENTRIES")
        .map(|s| {
            s.parse().map_err(|_| ConfigError::Invalid {
                name: "HUGINN_EBPF_SYN_MAP_MAX_ENTRIES".to_string(),
                value: s.clone(),
                reason: "must be a positive integer".to_string(),
            })
        })
        .transpose()
        .map(|opt| opt.unwrap_or(huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES))?;

    let metrics_listen_addr = get_var("HUGINN_EBPF_METRICS_ADDR")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_METRICS_ADDR".to_string() })?;

    let metrics_port_str = get_var("HUGINN_EBPF_METRICS_PORT")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_METRICS_PORT".to_string() })?;
    let metrics_port: u16 = metrics_port_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_METRICS_PORT".to_string(),
        value: metrics_port_str.clone(),
        reason: "must be a valid port number (1-65535)".to_string(),
    })?;

    let capture = resolve_capture_backend(&get_var)?;

    Ok(Config {
        interface,
        dst_ip_v4,
        dst_ip_v6,
        dst_port,
        pin_path,
        syn_map_max_entries,
        capture,
        metrics_listen_addr,
        metrics_port,
    })
}

/// Resolve the capture backend from env.
///
/// `HUGINN_EBPF_CAPTURE` (`xdp-native` | `xdp-skb` | `tc`) is the explicit selector and takes
/// precedence. When unset, the deprecated `HUGINN_EBPF_XDP_MODE` (`native` | `skb`) is honored as
/// a back-compat alias. With neither set, the default is `xdp-native` (today's behavior).
///
/// On VLAN/bond edge interfaces, `tc` is the recommended value: generic XDP drops GRO-merged data
/// packets there, while TC clsact ingress never drops. See `data/ebpf-vlan-tc-capture.md`.
fn resolve_capture_backend(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<CaptureBackend, ConfigError> {
    if let Some(v) = get_var("HUGINN_EBPF_CAPTURE") {
        return match v.as_str() {
            "xdp-native" => Ok(CaptureBackend::Xdp(XdpAttachMode::Native)),
            "xdp-skb" => Ok(CaptureBackend::Xdp(XdpAttachMode::Skb)),
            "tc" => Ok(CaptureBackend::Tc),
            other => Err(ConfigError::Invalid {
                name: "HUGINN_EBPF_CAPTURE".to_string(),
                value: other.to_string(),
                reason: "must be 'xdp-native', 'xdp-skb', or 'tc'".to_string(),
            }),
        };
    }

    // Deprecated alias.
    match get_var("HUGINN_EBPF_XDP_MODE").as_deref() {
        Some("skb") => Ok(CaptureBackend::Xdp(XdpAttachMode::Skb)),
        Some("native") | None => Ok(CaptureBackend::Xdp(XdpAttachMode::Native)),
        Some(v) => Err(ConfigError::Invalid {
            name: "HUGINN_EBPF_XDP_MODE".to_string(),
            value: v.to_string(),
            reason: "must be 'native' or 'skb' (deprecated: prefer HUGINN_EBPF_CAPTURE)"
                .to_string(),
        }),
    }
}

/// Human-readable label for the resolved capture backend (for startup logging).
pub fn capture_label(backend: CaptureBackend) -> &'static str {
    match backend {
        CaptureBackend::Xdp(XdpAttachMode::Native) => "xdp-native",
        CaptureBackend::Xdp(XdpAttachMode::Skb) => "xdp-skb",
        CaptureBackend::Tc => "tc",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `get_var` closure from a list of (name, value) pairs.
    fn env_of(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    /// Assert the resolver returns `Ok(expected)`.
    fn assert_resolves(env: impl Fn(&str) -> Option<String>, expected: CaptureBackend) {
        let got = resolve_capture_backend(&env);
        assert!(matches!(got, Ok(b) if b == expected), "expected {expected:?}, got {got:?}");
    }

    #[test]
    fn capture_explicit_values_win() {
        assert_resolves(
            env_of(&[("HUGINN_EBPF_CAPTURE", "xdp-native")]),
            CaptureBackend::Xdp(XdpAttachMode::Native),
        );
        assert_resolves(
            env_of(&[("HUGINN_EBPF_CAPTURE", "xdp-skb")]),
            CaptureBackend::Xdp(XdpAttachMode::Skb),
        );
        assert_resolves(env_of(&[("HUGINN_EBPF_CAPTURE", "tc")]), CaptureBackend::Tc);
    }

    #[test]
    fn capture_takes_precedence_over_xdp_mode_alias() {
        assert_resolves(
            env_of(&[("HUGINN_EBPF_CAPTURE", "tc"), ("HUGINN_EBPF_XDP_MODE", "skb")]),
            CaptureBackend::Tc,
        );
    }

    #[test]
    fn xdp_mode_alias_is_honored_when_capture_unset() {
        assert_resolves(
            env_of(&[("HUGINN_EBPF_XDP_MODE", "skb")]),
            CaptureBackend::Xdp(XdpAttachMode::Skb),
        );
        assert_resolves(
            env_of(&[("HUGINN_EBPF_XDP_MODE", "native")]),
            CaptureBackend::Xdp(XdpAttachMode::Native),
        );
    }

    #[test]
    fn default_is_xdp_native() {
        assert_resolves(env_of(&[]), CaptureBackend::Xdp(XdpAttachMode::Native));
    }

    #[test]
    fn invalid_capture_value_is_rejected() {
        let env = env_of(&[("HUGINN_EBPF_CAPTURE", "tcx")]);
        assert!(matches!(
            resolve_capture_backend(&env),
            Err(ConfigError::Invalid { ref name, .. }) if name == "HUGINN_EBPF_CAPTURE"
        ));
    }

    #[test]
    fn invalid_xdp_mode_alias_is_rejected() {
        let env = env_of(&[("HUGINN_EBPF_XDP_MODE", "generic")]);
        assert!(matches!(
            resolve_capture_backend(&env),
            Err(ConfigError::Invalid { ref name, .. }) if name == "HUGINN_EBPF_XDP_MODE"
        ));
    }

    #[test]
    fn labels_round_trip() {
        assert_eq!(capture_label(CaptureBackend::Xdp(XdpAttachMode::Native)), "xdp-native");
        assert_eq!(capture_label(CaptureBackend::Xdp(XdpAttachMode::Skb)), "xdp-skb");
        assert_eq!(capture_label(CaptureBackend::Tc), "tc");
    }

    // ── from_env ──────────────────────────────────────────────────────────────

    /// The minimal set of required env vars (no optional ones), for happy-path tests.
    const REQUIRED: &[(&str, &str)] = &[
        ("HUGINN_EBPF_INTERFACE", "eth0"),
        ("HUGINN_EBPF_DST_IP_V4", "10.0.0.1"),
        ("HUGINN_EBPF_DST_PORT", "8443"),
        ("HUGINN_EBPF_METRICS_ADDR", "0.0.0.0"),
        ("HUGINN_EBPF_METRICS_PORT", "9100"),
    ];

    /// `REQUIRED` plus the given extra pairs.
    fn required_with(extra: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let mut pairs: Vec<(&'static str, &'static str)> = REQUIRED.to_vec();
        pairs.extend_from_slice(extra);
        env_of(&pairs)
    }

    /// Parse `from_env`, panicking with a readable message on error.
    fn parse_ok(env: impl Fn(&str) -> Option<String>) -> Config {
        match from_env(env) {
            Ok(cfg) => cfg,
            Err(e) => panic!("expected Ok config, got {e:?}"),
        }
    }

    #[test]
    fn from_env_minimal_applies_defaults() {
        let cfg = parse_ok(required_with(&[]));
        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.dst_ip_v4, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(cfg.dst_port, 8443);
        assert_eq!(cfg.metrics_listen_addr, "0.0.0.0");
        assert_eq!(cfg.metrics_port, 9100);
        assert_eq!(cfg.dst_ip_v6, Ipv6Addr::UNSPECIFIED);
        assert_eq!(cfg.pin_path, DEFAULT_PIN_PATH);
        assert_eq!(cfg.syn_map_max_entries, huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES);
        assert!(matches!(cfg.capture, CaptureBackend::Xdp(XdpAttachMode::Native)));
    }

    #[test]
    fn from_env_full_overrides_every_optional() {
        let cfg = parse_ok(required_with(&[
            ("HUGINN_EBPF_DST_IP_V6", "2001:db8::1"),
            ("HUGINN_EBPF_PIN_PATH", "/run/bpf/huginn"),
            ("HUGINN_EBPF_SYN_MAP_MAX_ENTRIES", "16384"),
            ("HUGINN_EBPF_CAPTURE", "tc"),
        ]));
        assert_eq!(cfg.dst_ip_v6, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        assert_eq!(cfg.pin_path, "/run/bpf/huginn");
        assert_eq!(cfg.syn_map_max_entries, 16384);
        assert!(matches!(cfg.capture, CaptureBackend::Tc));
    }

    #[test]
    fn from_env_missing_required_vars_are_reported() {
        for missing in [
            "HUGINN_EBPF_INTERFACE",
            "HUGINN_EBPF_DST_IP_V4",
            "HUGINN_EBPF_DST_PORT",
            "HUGINN_EBPF_METRICS_ADDR",
            "HUGINN_EBPF_METRICS_PORT",
        ] {
            let pairs: Vec<(&str, &str)> = REQUIRED
                .iter()
                .copied()
                .filter(|(k, _)| *k != missing)
                .collect();
            let result = from_env(env_of(&pairs));
            assert!(
                matches!(result, Err(ConfigError::Missing { ref name }) if name == missing),
                "removing {missing} should report it missing, got {result:?}"
            );
        }
    }

    #[test]
    fn from_env_invalid_values_are_reported() {
        for (name, bad) in [
            ("HUGINN_EBPF_DST_IP_V4", "not-an-ip"),
            ("HUGINN_EBPF_DST_IP_V6", "::gg::"),
            ("HUGINN_EBPF_DST_PORT", "70000"),
            ("HUGINN_EBPF_METRICS_PORT", "-1"),
            ("HUGINN_EBPF_SYN_MAP_MAX_ENTRIES", "lots"),
        ] {
            let result = from_env(required_with(&[(name, bad)]));
            assert!(
                matches!(result, Err(ConfigError::Invalid { name: ref n, .. }) if n == name),
                "{name}={bad} should be rejected as invalid, got {result:?}"
            );
        }
    }

    #[test]
    fn from_env_wires_deprecated_xdp_mode_alias() {
        let cfg = parse_ok(required_with(&[("HUGINN_EBPF_XDP_MODE", "skb")]));
        assert!(matches!(cfg.capture, CaptureBackend::Xdp(XdpAttachMode::Skb)));
    }
}
