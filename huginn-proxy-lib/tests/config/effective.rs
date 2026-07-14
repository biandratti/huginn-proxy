use huginn_proxy_lib::config::{ConfigParser, EffectiveConfigView, TomlParser};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const CONFIG: &str = r#"
listen = { addrs = ["127.0.0.1:7000"], proxy_protocol = { mode = "optional" } }
backends = [{ address = "backend:9000" }]
headers = { request = { add = [
  { name = "Authorization", value = "global-secret" }
] } }

[[domains]]
host = "api.example.com"
cert_path = "/run/secrets/server-certificate.pem"
key_path = "/run/secrets/private-key.pem"
headers = { request = { add = [
  { name = "X-Domain-Token", value = "domain-secret" }
] } }
routes = [{
  prefix = "/api",
  backend = "backend:9000",
  headers = { response = { add = [
    { name = "X-Route-Token", value = "route-secret" }
  ] } }
}]

[tls]
alpn = ["h2", "http/1.1"]

[tls.client_auth]
required = { ca_cert_path = "/run/secrets/client-ca.pem" }

[security.headers]
custom = [{ name = "X-Security-Token", value = "security-secret" }]

[security.headers.csp]
enabled = true
policy = "default-src 'self'; connect-src https://secret.internal"
"#;

#[test]
fn effective_config_redacts_sensitive_values() -> TestResult {
    let config = TomlParser.parse(CONFIG)?;
    let parts = config.into_parts();
    let output =
        EffectiveConfigView::new(&parts.static_cfg, &parts.dynamic_cfg).to_pretty_json()?;

    for secret in [
        "global-secret",
        "domain-secret",
        "route-secret",
        "security-secret",
        "/run/secrets/server-certificate.pem",
        "/run/secrets/private-key.pem",
        "/run/secrets/client-ca.pem",
        "https://secret.internal",
    ] {
        assert!(!output.contains(secret), "effective config leaked sensitive value: {secret}");
    }

    assert!(output.contains("<redacted>"));
    assert!(output.contains("Authorization"));
    assert!(output.contains("X-Domain-Token"));
    assert!(output.contains("X-Route-Token"));
    assert!(output.contains("X-Security-Token"));
    Ok(())
}

#[test]
fn effective_config_reports_applied_values_and_defaults() -> TestResult {
    let config = TomlParser.parse(CONFIG)?;
    let parts = config.into_parts();
    let output =
        EffectiveConfigView::new(&parts.static_cfg, &parts.dynamic_cfg).to_pretty_json()?;
    let value: Value = serde_json::from_str(&output)?;

    assert_eq!(value["static"]["listen"]["proxy_protocol"]["mode"], "optional");
    assert_eq!(value["static"]["listen"]["proxy_protocol"]["header_timeout_ms"], 100);
    assert_eq!(value["static"]["max_connections"], 512);
    assert_eq!(value["static"]["tls"]["client_auth"]["mode"], "required");
    assert_eq!(value["static"]["tls"]["client_auth"]["ca_certificate_configured"], true);
    assert_eq!(value["dynamic"]["domains"][0]["cert_configured"], true);
    assert_eq!(value["dynamic"]["domains"][0]["private_key_configured"], true);
    assert_eq!(value["dynamic"]["headers"]["request"]["add"][0]["value"], "<redacted>");
    assert_eq!(value["dynamic"]["security"]["headers"]["csp"]["policy"], "<redacted>");
    Ok(())
}

#[test]
fn effective_config_json_is_deterministic() -> TestResult {
    let first = TomlParser.parse(CONFIG)?.into_parts();
    let second = TomlParser.parse(CONFIG)?.into_parts();

    let first_json =
        EffectiveConfigView::new(&first.static_cfg, &first.dynamic_cfg).to_pretty_json()?;
    let second_json =
        EffectiveConfigView::new(&second.static_cfg, &second.dynamic_cfg).to_pretty_json()?;

    assert_eq!(first_json, second_json);
    Ok(())
}
