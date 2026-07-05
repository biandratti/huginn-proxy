use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use huginn_proxy_lib::config::load_from_path;

fn tmp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("huginn-{nanos}-{name}.toml"))
}

#[test]
fn loads_minimal_config() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("minimal");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [
  { address = "localhost:9000" }
]
"#;
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert_eq!(cfg.listen.addrs[0].to_string(), "127.0.0.1:0");
    assert_eq!(cfg.backends.len(), 1);
    assert!(cfg.domains.is_empty());
    assert!(cfg.tls.is_none());
    Ok(())
}

#[test]
fn loads_domains_and_tls() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("domains");

    let cert_path = tmp_path("server.crt");
    let key_path = tmp_path("server.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;

    let toml = format!(
        r#"
listen = {{ addrs = ["127.0.0.1:0"] }}
backends = [
  {{ address = "backend-a:9000" }},
  {{ address = "backend-b:9000" }}
]

[tls]
alpn = ["h2"]

[[domains]]
host = "api.example.com"
cert = {{ type = "file", cert_path = "{}", key_path = "{}" }}
routes = [
  {{ prefix = "/api", backend = "backend-a:9000" }},
  {{ prefix = "/", backend = "backend-b:9000" }}
]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert_eq!(cfg.backends.len(), 2);
    assert_eq!(cfg.domains.len(), 1);
    assert_eq!(cfg.domains[0].routes.len(), 2);
    assert_eq!(
        cfg.domains[0].cert_file().map(|(c, _)| c),
        Some(cert_path.display().to_string().as_str())
    );
    let tls = cfg.tls.ok_or("tls missing")?;
    assert_eq!(tls.alpn, vec!["h2"]);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn normalizes_domain_host_to_lowercase() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("host-case");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "API.Example.COM"
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    assert_eq!(cfg.domains[0].host.as_deref(), Some("api.example.com"));
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_duplicate_domain_host() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("dup-host");
    // Different case → still a duplicate after normalization.
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "API.example.com"

[[domains]]
host = "api.example.com"
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject duplicate domain host"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("Duplicate domain host"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_multiple_catch_all_domains() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("multi-catchall");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "b:9000" }]

[[domains]]
# no host → catch-all

[[domains]]
# no host → second catch-all
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject multiple catch-all domains"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("Multiple catch-all"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn loads_per_domain_security_override() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::config::IpFilterMode;

    let path = tmp_path("domain-security");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.ip_filter]
mode = "denylist"
denylist = ["10.0.0.0/8"]

[security.rate_limit]
enabled = true
requests_per_second = 1000

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]

[domains.security.ip_filter]
mode = "allowlist"
allowlist = ["192.168.0.0/16"]

[domains.security.rate_limit]
enabled = true
requests_per_second = 5
burst = 5

[domains.security.headers.hsts]
enabled = true
max_age = 600
"#;
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    let security = cfg.domains[0]
        .security
        .as_ref()
        .ok_or("domain security should be present")?;

    let ip_filter = security
        .ip_filter
        .as_ref()
        .ok_or("ip_filter should be present")?;
    assert_eq!(ip_filter.mode, IpFilterMode::Allowlist);
    assert_eq!(ip_filter.allowlist.len(), 1);
    assert!(ip_filter.denylist.is_empty());

    let rate_limit = security
        .rate_limit
        .as_ref()
        .ok_or("rate_limit should be present")?;
    assert!(rate_limit.enabled);
    assert_eq!(rate_limit.requests_per_second, 5);
    assert_eq!(rate_limit.burst, 5);

    let headers = security
        .headers
        .as_ref()
        .ok_or("headers should be present")?;
    assert!(headers.hsts.enabled);
    assert_eq!(headers.hsts.max_age, 600);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn loads_per_route_security_override() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::config::{IpFilterMode, LimitBy};

    let path = tmp_path("route-security");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[[domains]]
host = "api.example.com"

[[domains.routes]]
prefix = "/"
backend = "backend:9000"

[[domains.routes]]
prefix = "/admin"
backend = "backend:9000"

[domains.routes.security.ip_filter]
mode = "allowlist"
allowlist = ["10.1.0.0/16"]

[domains.routes.security.rate_limit]
enabled = true
requests_per_second = 7
burst = 9
limit_by = "route"

[domains.routes.security.headers.csp]
enabled = true
policy = "default-src 'none'"
"#;
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    // Routes are sorted longest-prefix-first, so "/admin" comes before "/".
    let admin = cfg.domains[0]
        .routes
        .iter()
        .find(|r| r.prefix == "/admin")
        .ok_or("admin route should be present")?;
    let security = admin
        .security
        .as_ref()
        .ok_or("route security should be present")?;

    let ip_filter = security
        .ip_filter
        .as_ref()
        .ok_or("route ip_filter should be present")?;
    assert_eq!(ip_filter.mode, IpFilterMode::Allowlist);
    assert_eq!(ip_filter.allowlist.len(), 1);

    let rate_limit = security
        .rate_limit
        .as_ref()
        .ok_or("route rate_limit should be present")?;
    assert!(rate_limit.enabled);
    assert_eq!(rate_limit.requests_per_second, 7);
    assert_eq!(rate_limit.burst, 9);
    assert_eq!(rate_limit.limit_by, LimitBy::Route);

    let headers = security
        .headers
        .as_ref()
        .ok_or("route headers should be present")?;
    assert!(headers.csp.enabled);
    assert_eq!(headers.csp.policy, "default-src 'none'");

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn audit_warns_when_domain_override_disables_enabled_global_rate_limit(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::config::security_override_warnings;

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
    use huginn_proxy_lib::config::security_override_warnings;

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
    use huginn_proxy_lib::config::security_override_warnings;

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

#[test]
fn loads_acme_domain() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("acme-ok");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[tls]
alpn = ["h2"]

[acme]
contact_email = "ops@example.com"
cache_dir = "/var/lib/huginn-proxy/acme"

[[domains]]
host = "api.example.com"
cert = { type = "acme" }
routes = [{ prefix = "/", backend = "backend:9000" }]
"#;
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert!(cfg.domains[0].is_acme(true));
    assert!(cfg.domains[0].cert_file().is_none());
    let acme = cfg.acme.ok_or("acme block missing")?;
    assert_eq!(acme.contact_email, "ops@example.com");
    assert!(!acme.staging);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn acme_by_default_when_cert_omitted() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // A domain that omits `cert` while `[acme]` is configured is ACME-managed by default
    // (no per-domain flag needed). It must validate like an explicit `cert = { type = "acme" }`.
    let path = tmp_path("acme-default");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[tls]
alpn = ["h2"]

[acme]
contact_email = "ops@example.com"
cache_dir = "/var/lib/huginn-proxy/acme"

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]
"#;
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    // `cert` is absent on the wire …
    assert!(cfg.domains[0].cert.is_none());
    // … but resolves to ACME because `[acme]` is present (ACME-by-default).
    assert!(cfg.domains[0].is_acme(true));
    assert!(cfg.domains[0].cert_file().is_none());

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_acme_without_acme_block() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("acme-no-block");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[tls]
alpn = ["h2"]

[[domains]]
host = "api.example.com"
cert = { type = "acme" }
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject acme=true without [acme] block"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("requires a static [acme] block"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_acme_without_tls() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("acme-no-tls");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[acme]
contact_email = "ops@example.com"
cache_dir = "/tmp/acme"

[[domains]]
host = "api.example.com"
cert = { type = "acme" }
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject acme=true without [tls]"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("requires a [tls] block"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_acme_on_catch_all() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("acme-catchall");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[tls]
alpn = ["h2"]

[acme]
contact_email = "ops@example.com"
cache_dir = "/tmp/acme"

[[domains]]
# no host → catch-all
cert = { type = "acme" }
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject acme=true on catch-all domain"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("catch-all"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_acme_wildcard() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("acme-wildcard");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[tls]
alpn = ["h2"]

[acme]
contact_email = "ops@example.com"
cache_dir = "/tmp/acme"

[[domains]]
host = "*.example.com"
cert = { type = "acme" }
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject acme=true on wildcard host"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("wildcard"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_wildcard_under_global_acme() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("acme-global-wildcard");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[tls]
alpn = ["h2"]

[acme]
contact_email = "ops@example.com"
cache_dir = "/tmp/acme"

[[domains]]
host = "*.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject a wildcard host under global ACME"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("wildcard"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn allows_wildcard_file_cert_under_global_acme(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("acme-global-wildcard-file");
    let cert_path = tmp_path("wildcard.crt");
    let key_path = tmp_path("wildcard.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;
    let toml = format!(
        r#"
listen = {{ addrs = ["127.0.0.1:0"] }}
backends = [{{ address = "backend:9000" }}]

[tls]
alpn = ["h2"]

[acme]
contact_email = "ops@example.com"
cache_dir = "/tmp/acme"

[[domains]]
host = "*.example.com"
cert = {{ type = "file", cert_path = "{}", key_path = "{}" }}
routes = [{{ prefix = "/", backend = "backend:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    assert!(cfg.domains[0].cert_file().is_some());
    assert!(!cfg.domains[0].is_acme(true));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn rejects_acme_with_mtls_required() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("acme-mtls");
    let ca_path = tmp_path("ca.crt");
    fs::write(&ca_path, "dummy ca")?;
    let toml = format!(
        r#"
listen = {{ addrs = ["127.0.0.1:0"] }}
backends = [{{ address = "backend:9000" }}]

[tls]
alpn = ["h2"]
client_auth = {{ ca_cert_path = "{}" }}

[acme]
contact_email = "ops@example.com"
cache_dir = "/tmp/acme"

[[domains]]
host = "api.example.com"
cert = {{ type = "acme" }}
"#,
        ca_path.display()
    );
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject acme=true with client_auth = required"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("client_auth"), "got: {err}");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&ca_path);
    Ok(())
}

#[test]
fn rejects_tls_domain_without_cert() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("tls-no-cert");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[tls]
alpn = ["h2"]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject a [tls] domain without `cert`"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("must declare `cert`"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn allows_cert_less_domain_without_tls() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("plain-no-cert");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    assert!(cfg.tls.is_none());
    assert!(cfg.domains[0].cert.is_none());
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_invalid_health_check_timeout_greater_than_interval(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("bad-hc");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [
  { address = "localhost:9000", health_check = { interval_secs = 1, timeout_secs = 5 } }
]
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("load_from_path should reject invalid health_check invariants"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("timeout_secs") && msg.contains("interval_secs"),
        "expected timeout/interval error, got: {msg}"
    );
    let _ = fs::remove_file(&path);
    Ok(())
}
