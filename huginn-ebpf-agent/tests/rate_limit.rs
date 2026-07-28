use std::collections::HashMap;

use huginn_ebpf_agent::config::{from_env, ConfigError};

/// Build a `get_var` closure from a list of (name, value) pairs.
fn env_of(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    move |name: &str| map.get(name).cloned()
}

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
fn rate_limit_disabled_by_default_and_ignores_garbage_burst() {
    // With ENABLED unset (or false), BURST/WINDOW_SECONDS are never even read, so garbage
    // values there must not cause an error.
    let cfg = parse_ok(required_with(&[("HUGINN_EBPF_RATE_LIMIT_BURST", "not-a-number")]));
    assert!(!cfg.rate_limit.enabled);

    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "false"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "not-a-number"),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", "0"),
    ]));
    assert!(!cfg.rate_limit.enabled);
}

#[test]
fn rate_limit_enabled_converts_burst_and_window_seconds() {
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "2000"),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", "2"),
    ]));
    assert!(cfg.rate_limit.enabled);
    assert_eq!(cfg.rate_limit.threshold, 2000);
    assert_eq!(cfg.rate_limit.window_ns, 2_000_000_000);
}

#[test]
fn rate_limit_enabled_defaults_window_to_one_second() {
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "500"),
    ]));
    assert_eq!(cfg.rate_limit.window_ns, 1_000_000_000);
}

#[test]
fn rate_limit_enabled_without_burst_is_missing() {
    let result = from_env(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true")]));
    assert!(
        matches!(result, Err(ConfigError::Missing { ref name }) if name == "HUGINN_EBPF_RATE_LIMIT_BURST"),
        "enabling without a burst should report it missing, got {result:?}"
    );
}

#[test]
fn rate_limit_burst_zero_is_rejected() {
    let result = from_env(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "0"),
    ]));
    assert!(
        matches!(
            result,
            Err(ConfigError::Invalid { ref name, .. }) if name == "HUGINN_EBPF_RATE_LIMIT_BURST"
        ),
        "a zero burst would blackhole all SYNs and must be rejected, got {result:?}"
    );
}

#[test]
fn rate_limit_window_seconds_zero_is_rejected() {
    let result = from_env(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "500"),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", "0"),
    ]));
    assert!(
        matches!(
            result,
            Err(ConfigError::Invalid { ref name, .. }) if name == "HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS"
        ),
        "a zero window should be rejected, got {result:?}"
    );
}

#[test]
fn rate_limit_invalid_enabled_value_is_rejected() {
    let result = from_env(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", "maybe")]));
    assert!(
        matches!(
            result,
            Err(ConfigError::Invalid { ref name, .. }) if name == "HUGINN_EBPF_RATE_LIMIT_ENABLED"
        ),
        "an unparseable ENABLED value should be rejected, got {result:?}"
    );
}
