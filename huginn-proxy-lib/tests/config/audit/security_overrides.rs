use std::fs;

use huginn_proxy_lib::config::{load_from_path, security_override_warnings};

use crate::config::tmp_path;

#[test]
fn audit_warns_when_domain_override_disables_enabled_global_rate_limit(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("audit-domain-rl");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.rate_limit]
enabled = true
requests_per_second = 100

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]

[domains.security.rate_limit]
enabled = false
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let warnings = security_override_warnings(&cfg);
    assert_eq!(warnings.len(), 1, "expected one finding, got: {warnings:?}");
    assert_eq!(warnings[0].scope, "domain 'api.example.com'");
    assert!(warnings[0].message.contains("rate_limit"));

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn audit_warns_when_route_headers_override_drops_global_csp(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("audit-route-csp");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.headers.csp]
enabled = true
policy = "default-src 'self'"

[[domains]]
host = "api.example.com"

[[domains.routes]]
prefix = "/admin"
backend = "backend:9000"

# Route sets a headers block that does NOT re-enable CSP → CSP dropped (whole-block replace).
[domains.routes.security.headers.hsts]
enabled = true
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let warnings = security_override_warnings(&cfg);
    assert_eq!(warnings.len(), 1, "expected one finding, got: {warnings:?}");
    assert!(warnings[0].scope.starts_with("route '/admin'"));
    assert!(warnings[0].message.contains("CSP"));

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn audit_silent_when_override_tightens_or_parent_inactive(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("audit-silent");
    // Global rate limit disabled; domain ENABLES it (tightening) → no footgun.
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]

[domains.security.rate_limit]
enabled = true
requests_per_second = 5
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    assert!(security_override_warnings(&cfg).is_empty());

    let _ = fs::remove_file(&path);
    Ok(())
}
