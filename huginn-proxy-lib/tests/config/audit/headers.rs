use std::fs;

use huginn_proxy_lib::config::{header_config_warnings, load_from_path};

use crate::config::tmp_path;

#[test]
fn header_audit_warns_on_duplicate_add_and_add_remove_conflict(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("hdr-dup");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[headers.request]
# X-Foo added twice (last wins) and also removed (contradictory).
add = [
  { name = "X-Foo", value = "a" },
  { name = "x-foo", value = "b" },
]
remove = ["X-Foo"]

[headers.response]
add = [{ name = "X-Bar", value = "1" }]
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let warnings = header_config_warnings(&cfg);
    assert_eq!(warnings.len(), 2, "expected dup + conflict, got: {warnings:?}");
    assert!(warnings.iter().all(|w| w.scope == "global headers"));
    assert!(warnings
        .iter()
        .any(|w| w.message.contains("added more than once")));
    assert!(warnings
        .iter()
        .any(|w| w.message.contains("both added and removed")));

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn header_audit_warns_on_duplicate_custom_security_header(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("hdr-custom-dup");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.headers]
custom = [
  { name = "X-Bar", value = "1" },
  { name = "X-BAR", value = "2" },
]
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let warnings = header_config_warnings(&cfg);
    assert_eq!(warnings.len(), 1, "expected one finding, got: {warnings:?}");
    assert_eq!(warnings[0].scope, "global security headers");
    assert!(warnings[0].message.contains("listed more than once"));

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn header_audit_silent_on_cross_scope_override(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("hdr-cross-scope");
    // Same header name at global and domain scope is an intentional override, not a duplicate.
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[headers.request]
add = [{ name = "X-Foo", value = "global" }]

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]

[domains.headers.request]
add = [{ name = "X-Foo", value = "domain" }]
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    assert!(header_config_warnings(&cfg).is_empty());

    let _ = fs::remove_file(&path);
    Ok(())
}
