use std::collections::HashMap;

use huginn_ebpf_agent::config::{
    CaptureBackend, ConfigError, XdpAttachMode, env, resolve_capture_backend,
};

/// Build a `get_var` closure from a list of (name, value) pairs.
fn env_of(pairs: Vec<(&'static str, &'static str)>) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
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
        env_of(vec![(env::CAPTURE, "xdp-native")]),
        CaptureBackend::Xdp(XdpAttachMode::Native),
    );
    assert_resolves(
        env_of(vec![(env::CAPTURE, "xdp-skb")]),
        CaptureBackend::Xdp(XdpAttachMode::Skb),
    );
    assert_resolves(env_of(vec![(env::CAPTURE, "tc")]), CaptureBackend::Tc);
}

#[test]
fn default_is_xdp_native() {
    assert_resolves(env_of(vec![]), CaptureBackend::Xdp(XdpAttachMode::Native));
}

#[test]
fn capture_is_case_insensitive_and_trims_whitespace() {
    assert_resolves(env_of(vec![(env::CAPTURE, " TC ")]), CaptureBackend::Tc);
    assert_resolves(
        env_of(vec![(env::CAPTURE, "XDP-SKB")]),
        CaptureBackend::Xdp(XdpAttachMode::Skb),
    );
    assert_resolves(
        env_of(vec![(env::CAPTURE, " Xdp-Native ")]),
        CaptureBackend::Xdp(XdpAttachMode::Native),
    );
}

#[test]
fn invalid_capture_value_is_rejected() {
    let vars = env_of(vec![(env::CAPTURE, "tcx")]);
    assert!(matches!(
        resolve_capture_backend(&vars),
        Err(ConfigError::Invalid { ref name, .. }) if name == env::CAPTURE
    ));
}

#[test]
fn labels_round_trip() {
    assert_eq!(CaptureBackend::Xdp(XdpAttachMode::Native).as_str(), "xdp-native");
    assert_eq!(CaptureBackend::Xdp(XdpAttachMode::Skb).as_str(), "xdp-skb");
    assert_eq!(CaptureBackend::Tc.as_str(), "tc");
}
