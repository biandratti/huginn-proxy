use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use huginn_ebpf_agent::config::{
    from_env, CaptureBackend, ConfigError, EbpfLogLevel, HealthFormat, XdpAttachMode,
    DEFAULT_PIN_PATH,
};

/// Build a `get_var` closure from a list of (name, value) pairs.
fn env_of(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    move |name: &str| map.get(name).cloned()
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
fn parse_ok(env: impl Fn(&str) -> Option<String>) -> huginn_ebpf_agent::config::Config {
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
    assert_eq!(cfg.log_level, EbpfLogLevel::Off, "log level must default to off");
    assert!(!cfg.rate_limit.enabled(), "rate limiter must default to disabled");
    assert_eq!(cfg.health_format, HealthFormat::Json);
}

#[test]
fn from_env_full_overrides_every_optional() {
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_DST_IP_V6", "2001:db8::1"),
        ("HUGINN_EBPF_PIN_PATH", "/run/bpf/huginn"),
        ("HUGINN_EBPF_SYN_MAP_MAX_ENTRIES", "16384"),
        ("HUGINN_EBPF_CAPTURE", "tc"),
        ("HUGINN_EBPF_LOG_LEVEL", "debug"),
        ("HUGINN_EBPF_HEALTH_FORMAT", "text"),
    ]));
    assert_eq!(cfg.dst_ip_v6, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
    assert_eq!(cfg.pin_path, "/run/bpf/huginn");
    assert_eq!(cfg.syn_map_max_entries, 16384);
    assert!(matches!(cfg.capture, CaptureBackend::Tc));
    assert_eq!(
        cfg.log_level,
        EbpfLogLevel::Debug,
        "HUGINN_EBPF_LOG_LEVEL=debug should be parsed"
    );
    assert_eq!(cfg.health_format, HealthFormat::Text);
}

#[test]
fn log_level_accepts_all_levels_case_insensitively() {
    for (raw, expected) in [
        (" off ", EbpfLogLevel::Off),
        ("ERROR", EbpfLogLevel::Error),
        ("Warn", EbpfLogLevel::Warn),
        ("info", EbpfLogLevel::Info),
        ("debug", EbpfLogLevel::Debug),
        ("TRACE", EbpfLogLevel::Trace),
    ] {
        let cfg = parse_ok(required_with(&[("HUGINN_EBPF_LOG_LEVEL", raw)]));
        assert_eq!(cfg.log_level, expected, "{raw:?} should parse to {expected:?}");
    }
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
        ("HUGINN_EBPF_LOG_LEVEL", "verbose"),
        ("HUGINN_EBPF_HEALTH_FORMAT", "xml"),
    ] {
        let result = from_env(required_with(&[(name, bad)]));
        assert!(
            matches!(result, Err(ConfigError::Invalid { name: ref n, .. }) if n == name),
            "{name}={bad} should be rejected as invalid, got {result:?}"
        );
    }
}
