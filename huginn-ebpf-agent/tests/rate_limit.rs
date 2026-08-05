use std::collections::HashMap;

use huginn_ebpf_agent::config::{
    from_env, ConfigError, SynRateLimit, DEFAULT_BURST, DEFAULT_WINDOW_SECONDS,
};

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
fn from_burst_window_only_builds_enforceable_limiters() {
    // Fields are private: the only constructors are `disabled` / `from_burst_window`, and the
    // latter must not hand out an enabled limiter that can never fire (or never rotate).
    assert_eq!(SynRateLimit::from_burst_window(false, 100, 1), SynRateLimit::disabled());
    assert_eq!(SynRateLimit::from_burst_window(true, 0, 1), SynRateLimit::disabled());
    assert_eq!(SynRateLimit::from_burst_window(true, 65_535, 1), SynRateLimit::disabled());
    assert_eq!(SynRateLimit::from_burst_window(true, 100, 0), SynRateLimit::disabled());
    assert_eq!(SynRateLimit::from_burst_window(true, 100, 3601), SynRateLimit::disabled());

    let ok = SynRateLimit::from_burst_window(true, 100, 2);
    assert!(ok.enabled());
    assert_eq!(ok.threshold(), 100);
    assert_eq!(ok.window_ns(), NANOS_PER_SEC.saturating_mul(2));
}

#[test]
fn rate_limit_disabled_by_default_and_ignores_garbage_burst() {
    // With ENABLED unset, BURST/WINDOW_SECONDS are never read, so garbage there must not error.
    // Explicit `false` is covered by rate_limit_enabled_tolerates_case_and_surrounding_whitespace.
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "not-a-number"),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", "0"),
    ]));
    assert!(!cfg.rate_limit.enabled());
}

#[test]
fn rate_limit_enabled_converts_burst_and_window_seconds() {
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "2000"),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", "2"),
    ]));
    assert!(cfg.rate_limit.enabled());
    assert_eq!(cfg.rate_limit.threshold(), 2000);
    assert_eq!(cfg.rate_limit.window_ns(), NANOS_PER_SEC.saturating_mul(2));
}

#[test]
fn rate_limit_enabled_defaults_the_window() {
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "500"),
    ]));
    assert_eq!(cfg.rate_limit.window_ns(), DEFAULT_WINDOW_SECONDS.saturating_mul(NANOS_PER_SEC));
}

#[test]
fn rate_limit_enabled_without_burst_falls_back_to_the_default() {
    let cfg = parse_ok(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true")]));
    assert!(cfg.rate_limit.enabled());
    assert_eq!(cfg.rate_limit.threshold(), DEFAULT_BURST);
}

#[test]
fn rate_limit_unusable_burst_is_rejected() {
    // A burst at or above 65535 is never crossed (the sketch counts in u16), so the limiter would
    // pass every SYN. Zero would skip every SYN. Neither is silently accepted.
    for burst in ["0", "65535", "131070", "5000000000", "not-a-number", "-1"] {
        let result = from_env(required_with(&[
            ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
            ("HUGINN_EBPF_RATE_LIMIT_BURST", burst),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::Invalid { ref name, .. })
                    if name == "HUGINN_EBPF_RATE_LIMIT_BURST"
            ),
            "burst {burst} is unusable and must be rejected, got {result:?}"
        );
    }
}

#[test]
fn rate_limit_accepts_the_highest_usable_burst() {
    assert_eq!(SynRateLimit::MAX_THRESHOLD, 65_534, "the literal below tracks this ceiling");
    let cfg = parse_ok(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "65534"),
    ]));
    assert_eq!(cfg.rate_limit.threshold(), 65_534);
    assert!(cfg.rate_limit.enabled(), "the ceiling itself is still enforceable");
}

#[test]
fn rate_limit_unusable_window_seconds_is_rejected() {
    // 0 would never rotate. Past the ceiling a source that crosses `burst` stays uncaptured for
    // the rest of the window, which is a blocklist rather than a rate limit.
    for window in ["0", "not-a-number", "-3", "3601", "10000000000000"] {
        let result = from_env(required_with(&[
            ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
            ("HUGINN_EBPF_RATE_LIMIT_BURST", "500"),
            ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", window),
        ]));
        assert!(
            matches!(
                result,
                Err(ConfigError::Invalid { ref name, .. })
                    if name == "HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS"
            ),
            "window {window} is unusable and must be rejected, got {result:?}"
        );
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
    assert_eq!(cfg.rate_limit.window_ns(), NANOS_PER_SEC.saturating_mul(3600));
    assert!(cfg.rate_limit.enabled(), "the ceiling itself is still usable");
}

#[test]
fn rate_limit_invalid_enabled_value_is_rejected() {
    let result = from_env(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", "maybe")]));
    assert!(
        matches!(
            result,
            Err(ConfigError::Invalid { ref name, .. })
                if name == "HUGINN_EBPF_RATE_LIMIT_ENABLED"
        ),
        "an unparseable ENABLED value must be rejected, got {result:?}"
    );
}

#[test]
fn rate_limit_enabled_tolerates_case_and_surrounding_whitespace() {
    // Values are trimmed and lowercased before parsing. `bool`'s own FromStr takes only
    // exact "true"/"false", so without that a `TRUE` in a compose file or a
    // trailing space out of a `.env` would leave the limiter silently off.
    for raw in ["true", "TRUE", "True", " true ", "true\n"] {
        let cfg = parse_ok(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", raw)]));
        assert!(cfg.rate_limit.enabled(), "ENABLED={raw:?} must enable the limiter");
    }
    for raw in ["false", "FALSE", " False "] {
        let cfg = parse_ok(required_with(&[("HUGINN_EBPF_RATE_LIMIT_ENABLED", raw)]));
        assert!(!cfg.rate_limit.enabled(), "ENABLED={raw:?} must leave the limiter off");
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
        cfg.rate_limit.threshold(),
        500,
        "a padded burst must not fall back to the default"
    );
    assert_eq!(
        cfg.rate_limit.window_ns(),
        NANOS_PER_SEC.saturating_mul(2),
        "a padded window must be honoured"
    );
}

#[test]
fn a_rejected_value_names_itself_and_its_reason() {
    // The error leaves `main` as a `Result`, so it prints even before the tracing subscriber is
    // installed. It has to identify the variable, the rejected value and the accepted range.
    let result = from_env(required_with(&[
        ("HUGINN_EBPF_RATE_LIMIT_ENABLED", "true"),
        ("HUGINN_EBPF_RATE_LIMIT_BURST", "500"),
        ("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS", "4000"),
    ]));
    match result {
        Err(ConfigError::Invalid { name, value, reason }) => {
            assert_eq!(name, "HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS");
            assert_eq!(value, "4000", "the rejected value is reported verbatim");
            assert!(
                reason.contains("3600"),
                "the reason must state the accepted range, got {reason:?}"
            );
        }
        other => panic!("expected an Invalid error for the window, got {other:?}"),
    }
}
