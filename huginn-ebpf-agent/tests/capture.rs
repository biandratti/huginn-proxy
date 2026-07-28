use huginn_ebpf_agent::config::{
    resolve_capture_backend, CaptureBackend, ConfigError, XdpAttachMode,
};

/// Build a `get_var` closure from a list of (name, value) pairs.
fn env_of(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    use std::collections::HashMap;
    let map: HashMap<String, String> = pairs
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
fn default_is_xdp_native() {
    assert_resolves(env_of(&[]), CaptureBackend::Xdp(XdpAttachMode::Native));
}

#[test]
fn capture_is_case_insensitive_and_trims_whitespace() {
    assert_resolves(env_of(&[("HUGINN_EBPF_CAPTURE", " TC ")]), CaptureBackend::Tc);
    assert_resolves(
        env_of(&[("HUGINN_EBPF_CAPTURE", "XDP-SKB")]),
        CaptureBackend::Xdp(XdpAttachMode::Skb),
    );
    assert_resolves(
        env_of(&[("HUGINN_EBPF_CAPTURE", " Xdp-Native ")]),
        CaptureBackend::Xdp(XdpAttachMode::Native),
    );
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
fn labels_round_trip() {
    assert_eq!(CaptureBackend::Xdp(XdpAttachMode::Native).as_str(), "xdp-native");
    assert_eq!(CaptureBackend::Xdp(XdpAttachMode::Skb).as_str(), "xdp-skb");
    assert_eq!(CaptureBackend::Tc.as_str(), "tc");
}
