use std::fs;

use huginn_proxy_lib::config::{load_from_path, proxy_protocol_trust_warnings};

use crate::config::tmp_path;

fn warnings_for(name: &str, toml: &str) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path(name);
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;
    let warnings = proxy_protocol_trust_warnings(&cfg);
    let _ = fs::remove_file(&path);
    assert!(warnings.iter().all(|w| w.scope == "proxy_protocol"), "{warnings:?}");
    Ok(warnings.len())
}

#[test]
fn require_with_empty_trusted_proxies_warns() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"], proxy_protocol = { mode = "require" } }
backends = [{ address = "backend:9000" }]
"#;
    assert_eq!(warnings_for("pp-require-empty", toml)?, 1);
    Ok(())
}

#[test]
fn optional_with_empty_trusted_proxies_warns(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"], proxy_protocol = { mode = "optional" } }
backends = [{ address = "backend:9000" }]
"#;
    assert_eq!(warnings_for("pp-optional-empty", toml)?, 1);
    Ok(())
}

#[test]
fn off_mode_never_warns() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"], proxy_protocol = { mode = "off" } }
backends = [{ address = "backend:9000" }]
"#;
    assert_eq!(warnings_for("pp-off", toml)?, 0);
    Ok(())
}

#[test]
fn require_with_trusted_proxies_does_not_warn(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"], proxy_protocol = { mode = "require" } }
backends = [{ address = "backend:9000" }]

[security]
trusted_proxies = ["10.0.0.0/8"]
"#;
    assert_eq!(warnings_for("pp-require-trusted", toml)?, 0);
    Ok(())
}
