use std::fs;

use huginn_proxy_lib::config::{
    all_warnings, header_config_warnings, load_from_path, rate_limit_warnings,
    security_override_warnings, trusted_proxies_warnings,
};

use crate::config::tmp_path;

#[test]
fn all_warnings_aggregates_every_audit() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("aggregate-all");
    // Triggers all three audits at once:
    //  - header duplicate (global headers)
    //  - trusted_proxies trust-all
    //  - security override dropping a globally-enabled rate limit
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security]
trusted_proxies = { cidrs = ["0.0.0.0/0"] }

[security.rate_limit]
enabled = true
requests_per_second = 100

[headers.request]
add = [
  { name = "X-Foo", value = "a" },
  { name = "x-foo", value = "b" },
]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]

[domains.security.rate_limit]
enabled = false
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let expected = header_config_warnings(&cfg).len()
        + rate_limit_warnings(&cfg).len()
        + security_override_warnings(&cfg).len()
        + trusted_proxies_warnings(&cfg).len();
    let all = all_warnings(&cfg);

    assert_eq!(all.len(), expected, "all_warnings must sum every audit: {all:?}");
    assert!(expected >= 3, "fixture should trigger all three audits, got {expected}");
    assert!(all.iter().any(|w| w.scope == "global headers"));
    assert!(all.iter().any(|w| w.scope == "trusted_proxies"));
    assert!(all.iter().any(|w| w.scope == "domain 'api.example.com'"));

    let _ = fs::remove_file(&path);
    Ok(())
}
