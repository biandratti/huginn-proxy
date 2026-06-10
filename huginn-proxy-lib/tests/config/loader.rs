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
