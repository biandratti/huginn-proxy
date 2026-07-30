use std::collections::HashMap;

use huginn_ebpf_agent::config::{from_env, SynRateLimit, DEFAULT_BURST, DEFAULT_WINDOW_SECONDS};

const NANOS_PER_SEC: u64 = 1_000_000_000;

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
    // With ENABLED unset, BURST/WINDOW_SECONDS are never read, so garbage there must not error.
    // Explicit `false` is covered by rate_limit_enabled_tolerates_case_and_surrounding_whitespace.
    let cfg = parse_ok(required_with(&[
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
    assert_eq!(cfg.rate_limit.window_ns, NANOS_PER_SEC.saturating_mul(2));
}

#[test]
fn rate_limit_enabled_defaults_the_window() {
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "500"),
    ]));
    assert_eq!(cfg.rate_limit.window_ns, DEFAULT_WINDOW_SECONDS.saturating_mul(NANOS_PER_SEC));
}

#[test]
fn rate_limit_enabled_without_burst_falls_back_to_the_default() {
    let cfg = parse_ok(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true")]));
    assert!(cfg.rate_limit.enabled);
    assert_eq!(cfg.rate_limit.threshold, DEFAULT_BURST);
}

#[test]
fn rate_limit_unusable_burst_falls_back_to_the_default() {
    // A burst at or above 65535 is never crossed (the sketch counts in u16), so the limiter
    // would pass every SYN. Zero would skip every SYN. Both are logged at ERROR and replaced
    // with the default, so the agent still publishes its maps.
    for burst in ["0", "65535", "131070", "5000000000", "not-a-number", "-1"] {
        let cfg = parse_ok(required_with(&[
            ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
            ("HUGINN_EBPF_RATE_LIMIT_BURST", burst),
        ]));
        assert_eq!(
            cfg.rate_limit.threshold, DEFAULT_BURST,
            "burst {burst} is unusable and must fall back to the default"
        );
        assert!(cfg.rate_limit.enabled, "the limiter stays on with the default burst");
    }
}

#[test]
fn rate_limit_accepts_the_highest_usable_burst() {
    assert_eq!(SynRateLimit::MAX_THRESHOLD, 65_534, "the literal below tracks this ceiling");
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "65534"),
    ]));
    assert_eq!(cfg.rate_limit.threshold, 65_534);
    assert!(cfg.rate_limit.enabled, "the ceiling itself is still enforceable");
}

#[test]
fn rate_limit_unusable_window_seconds_falls_back_to_the_default() {
    // 0 would never rotate. Past the ceiling the counters saturate long before the window ends,
    // so a source that reaches `burst` stays uncaptured for the rest of it.
    for window in ["0", "not-a-number", "-3", "3601", "10000000000000"] {
        let cfg = parse_ok(required_with(&[
            ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
            ("HUGINN_EBPF_RATE_LIMIT_BURST", "500"),
            ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", window),
        ]));
        assert_eq!(
            cfg.rate_limit.window_ns,
            DEFAULT_WINDOW_SECONDS.saturating_mul(NANOS_PER_SEC),
            "window {window} is unusable and must fall back to the default"
        );
        assert_eq!(cfg.rate_limit.threshold, 500, "a valid burst is still honoured");
    }
}

#[test]
fn rate_limit_accepts_the_longest_usable_window() {
    assert_eq!(SynRateLimit::MAX_WINDOW_SECONDS, 3600, "the literal below tracks this ceiling");
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "500"),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", "3600"),
    ]));
    assert_eq!(cfg.rate_limit.window_ns, NANOS_PER_SEC.saturating_mul(3600));
    assert!(cfg.rate_limit.enabled, "the ceiling itself is still usable");
}

#[test]
fn rate_limit_invalid_enabled_value_falls_back_to_disabled() {
    let cfg = parse_ok(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", "maybe")]));
    assert!(
        !cfg.rate_limit.enabled,
        "an unparseable ENABLED value falls back to the default"
    );
}

#[test]
fn rate_limit_enabled_tolerates_case_and_surrounding_whitespace() {
    // Values are trimmed and lowercased before parsing. `bool`'s own FromStr takes only
    // exact "true"/"false", so without that a `TRUE` in a compose file or a
    // trailing space out of a `.env` would leave the limiter silently off.
    for raw in ["true", "TRUE", "True", " true ", "true\n"] {
        let cfg = parse_ok(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", raw)]));
        assert!(cfg.rate_limit.enabled, "ENABLED={raw:?} must enable the limiter");
    }
    for raw in ["false", "FALSE", " False "] {
        let cfg = parse_ok(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", raw)]));
        assert!(!cfg.rate_limit.enabled, "ENABLED={raw:?} must leave the limiter off");
    }
}

#[test]
fn rate_limit_burst_and_window_tolerate_surrounding_whitespace() {
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", " 500 "),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", " 2\n"),
    ]));
    assert_eq!(
        cfg.rate_limit.threshold, 500,
        "a padded burst must not fall back to the default"
    );
    assert_eq!(
        cfg.rate_limit.window_ns,
        NANOS_PER_SEC.saturating_mul(2),
        "a padded window must be honoured"
    );
}

#[test]
fn a_bad_rate_limit_never_fails_the_whole_config() {
    // The agent must still start and pin its maps: exiting here leaves the proxy waiting forever
    // on pinned maps that never appear, taking HTTP and TLS fingerprinting down with it.
    let result = from_env(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "yes-test"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "5000000000"),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", "-3"),
    ]));
    assert!(result.is_ok(), "rate-limit values must never be fatal, got {result:?}");
}
