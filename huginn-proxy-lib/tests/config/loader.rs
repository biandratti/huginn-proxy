use std::fs;

use huginn_proxy_lib::config::load_from_path;

use super::tmp_path;

#[test]
fn loads_minimal_config() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("minimal");
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
backends = [
  { address = "localhost:9000" }
]
"#;
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert_eq!(cfg.listen.port, Some(8080));
    assert_eq!(cfg.listen.address_v4, Some(vec!["127.0.0.1".to_string()]));
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
listen = {{ port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [
  {{ address = "backend-a:9000" }},
  {{ address = "backend-b:9000" }}
]

[tls]
alpn = ["h2"]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path  = "{}"
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
        cfg.domains[0].cert_path.as_deref(),
        Some(cert_path.display().to_string().as_str())
    );
    let tls = cfg.tls.ok_or("tls missing")?;
    assert_eq!(tls.alpn, Some(vec!["h2".to_string()]));

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn loads_domain_client_ca_path() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("domain-mtls");
    let cert_path = tmp_path("mtls-server.crt");
    let key_path = tmp_path("mtls-server.key");
    let ca_path = tmp_path("mtls-client-ca.crt");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;
    fs::write(&ca_path, "dummy ca")?;

    let toml = format!(
        r#"
listen = {{ port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "backend:9000" }}]

[tls]

[[domains]]
host = "secure.example.com"
cert_path = "{}"
key_path  = "{}"
client_ca_path = "{}"
routes = [{{ prefix = "/", backend = "backend:9000" }}]
"#,
        cert_path.display(),
        key_path.display(),
        ca_path.display()
    );
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert_eq!(
        cfg.domains[0].client_ca_path.as_deref(),
        Some(ca_path.display().to_string().as_str()),
        "client_ca_path must round-trip from config"
    );

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&ca_path);
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_client_ca_without_cert() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("mtls-no-cert");
    let ca_path = tmp_path("orphan-client-ca.crt");
    fs::write(&ca_path, "dummy ca")?;

    let toml = format!(
        r#"
listen = {{ port = 8080, port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "backend:9000" }}]

[tls]

[[domains]]
host = "secure.example.com"
client_ca_path = "{}"
"#,
        ca_path.display()
    );
    fs::write(&path, toml)?;

    let err = match load_from_path(&path) {
        Ok(_) => panic!("client_ca_path without cert_path/key_path must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("client_ca_path requires cert_path"), "got: {err}");

    let _ = fs::remove_file(&ca_path);
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_missing_client_ca_file() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("mtls-missing-ca");
    let cert_path = tmp_path("mtls2-server.crt");
    let key_path = tmp_path("mtls2-server.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;

    let toml = format!(
        r#"
listen = {{ port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "backend:9000" }}]

[tls]

[[domains]]
host = "secure.example.com"
cert_path = "{}"
key_path  = "{}"
client_ca_path = "/nonexistent/huginn-test/missing-ca.crt"
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;

    let err = match load_from_path(&path) {
        Ok(_) => panic!("a missing client CA file must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("client CA file not found"), "got: {err}");

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn normalizes_domain_host_to_lowercase() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("host-case");
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
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
fn normalizes_domain_host_trailing_dot() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("host-trailing-dot");
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "API.Example.COM."
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    assert_eq!(cfg.domains[0].host.as_deref(), Some("api.example.com"));
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_duplicate_domain_host_with_and_without_trailing_dot()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("dup-host-trailing-dot");
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "api.example.com."

[[domains]]
host = "api.example.com"
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("should reject duplicate domain host (with/without trailing dot)"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("Duplicate domain host"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_bare_dot_host() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("bare-dot-host");
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "."
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("a bare '.' host must not silently become an empty, unmatchable host"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("must not be empty"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_duplicate_domain_host() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("dup-host");
    // Different case → still a duplicate after normalization.
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
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
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
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
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
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
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
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
    assert_eq!(headers.csp.policy.expose(), "default-src 'none'");

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_domain_certs_without_a_tls_section()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tmp_path("no-tls.crt");
    let key_path = tmp_path("no-tls.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;

    let path = tmp_path("no-tls");
    let toml = format!(
        r#"
listen = {{ port = 8080, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path  = "{}"
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;

    let err = match load_from_path(&path) {
        Ok(_) => panic!("a domain cert without listen.port_tls should be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("port_tls"), "the error must point at the missing port: {err}");

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn accepts_a_plain_domain_without_a_tls_section()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("plain-domain");
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "b:9000" }]
"#;
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert!(cfg.tls.is_none());
    assert_eq!(cfg.domains.len(), 1);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rejects_invalid_health_check_timeout_greater_than_interval()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("bad-hc");
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
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

#[test]
fn http_only_rejects_domain_cert_even_with_tls_section()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = tmp_path("http-tls-section.crt");
    let key_path = tmp_path("http-tls-section.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;
    let path = tmp_path("http-only-cert-with-tls");
    let toml = format!(
        r#"
listen = {{ port = 8080, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[tls]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path = "{}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("HTTP-only listen must reject domain certs even when [tls] is present"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("port_tls"), "got: {err}");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn rejects_tls_section_without_port_tls() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("tls-no-port-tls");
    let toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[tls]
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("[tls] without listen.port_tls must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("port_tls"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn port_tls_without_tls_section_fills_default_alpn()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("port-tls-no-section");
    let cert_path = tmp_path("fill-alpn.crt");
    let key_path = tmp_path("fill-alpn.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;
    let toml = format!(
        r#"
listen = {{ port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path = "{}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    let tls = cfg.tls.ok_or("tls should be filled")?;
    assert_eq!(tls.alpn, Some(vec!["h2".to_string(), "http/1.1".to_string()]));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn explicit_alpn_including_empty_is_kept() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("explicit-alpn");
    let cert_path = tmp_path("explicit-alpn.crt");
    let key_path = tmp_path("explicit-alpn.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;
    let toml = format!(
        r#"
listen = {{ port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[tls]
alpn = []

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path = "{}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    let tls = cfg.tls.ok_or("tls missing")?;
    assert_eq!(tls.alpn, Some(Vec::new()));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn https_only_rejects_domain_without_cert() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let path = tmp_path("https-only-no-cert");
    let toml = r#"
listen = { port_tls = 8443, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "b:9000" }]
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("HTTPS-only domain without cert must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("cert_path"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn both_ports_reject_domain_without_cert() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("dual-plain-domain");
    let toml = r#"
listen = { port = 8080, port_tls = 8443, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "b:9000" }]
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("dual-listen domain without cert must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("cert_path"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn both_ports_reject_catchall_without_cert() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let path = tmp_path("dual-plain-catchall");
    let toml = r#"
listen = { port = 8080, port_tls = 8443, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[[domains]]
routes = [{ prefix = "/", backend = "b:9000" }]
"#;
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("dual-listen catch-all without cert must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("cert_path"), "got: {err}");
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn reload_validates_domains_against_running_listen()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::config::load_from_path_for_reload;

    let cert_path = tmp_path("reload-run.crt");
    let key_path = tmp_path("reload-run.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;

    let running_path = tmp_path("reload-running");
    let running_toml = format!(
        r#"
listen = {{ port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path = "{}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&running_path, running_toml)?;
    let running = load_from_path(&running_path)?;
    let parts = running.into_parts();

    let next_path = tmp_path("reload-next");
    let next_toml = r#"
listen = { port = 8080, address_v4 = ["127.0.0.1"] }
backends = [{ address = "b:9000" }]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "b:9000" }]
"#;
    fs::write(&next_path, next_toml)?;

    let err = match load_from_path_for_reload(&next_path, &parts.static_cfg) {
        Ok(_) => panic!("reload must reject dropping certs while port_tls is still running"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("cert_path"), "got: {err}");

    let _ = fs::remove_file(&running_path);
    let _ = fs::remove_file(&next_path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn dual_listen_allows_domains_to_share_cert_files()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("shared-cert");
    let cert_path = tmp_path("shared-cert.crt");
    let key_path = tmp_path("shared-cert.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;
    let toml = format!(
        r#"
listen = {{ port = 8080, port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[[domains]]
host = "api.example.com"
cert_path = "{cert}"
key_path = "{key}"
routes = [{{ prefix = "/", backend = "b:9000" }}]

[[domains]]
host = "docs.example.com"
cert_path = "{cert}"
key_path = "{key}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert = cert_path.display(),
        key = key_path.display(),
    );
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    assert_eq!(cfg.domains[0].cert_path, cfg.domains[1].cert_path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn listen_https_redirection_on_https_only_is_rejected()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("https-redir-one-port");
    let cert_path = tmp_path("redir-one.crt");
    let key_path = tmp_path("redir-one.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;
    let toml = format!(
        r#"
listen = {{ port_tls = 8443, https_redirection = true, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path = "{}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;
    let err = match load_from_path(&path) {
        Ok(_) => panic!("listen.https_redirection with a single port must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("listen.port"), "got: {err}");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn dual_listen_omitted_https_redirection_loads()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("https-redir-omit");
    let cert_path = tmp_path("redir-omit.crt");
    let key_path = tmp_path("redir-omit.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;
    let toml = format!(
        r#"
listen = {{ port = 8080, port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path = "{}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    assert!(huginn_proxy_lib::config::RuntimeListen::from(&cfg.listen).https_redirection);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}

#[test]
fn reload_https_redirection_uses_running_listen()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use huginn_proxy_lib::config::load_from_path_for_reload;

    let cert_path = tmp_path("redir-reload.crt");
    let key_path = tmp_path("redir-reload.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;

    let running_path = tmp_path("redir-running-dual");
    let running_toml = format!(
        r#"
listen = {{ port = 8080, port_tls = 8443, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path = "{}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&running_path, running_toml)?;
    let running = load_from_path(&running_path)?;
    let parts = running.into_parts();

    let next_path = tmp_path("redir-next-dual");
    let next_toml = format!(
        r#"
listen = {{ port = 8080, port_tls = 8443, https_redirection = false, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "b:9000" }}]

[[domains]]
host = "api.example.com"
cert_path = "{}"
key_path = "{}"
routes = [{{ prefix = "/", backend = "b:9000" }}]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&next_path, next_toml)?;

    let next = load_from_path_for_reload(&next_path, &parts.static_cfg)?;
    assert_eq!(next.listen.https_redirection, Some(false));
    assert!(
        huginn_proxy_lib::config::RuntimeListen::from(&parts.static_cfg.listen).https_redirection
    );

    let _ = fs::remove_file(&running_path);
    let _ = fs::remove_file(&next_path);
    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}
