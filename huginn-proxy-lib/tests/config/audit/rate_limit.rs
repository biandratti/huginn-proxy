use std::fs;

use huginn_proxy_lib::config::{load_from_path, rate_limit_warnings};

use crate::config::tmp_path;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn warns_on_enabled_rate_limit_with_zero_window() -> TestResult {
    let path = tmp_path("rl-zero-window");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.rate_limit]
enabled = true
window_seconds = 0
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let warnings = rate_limit_warnings(&cfg);
    assert_eq!(warnings.len(), 1, "expected one finding, got: {warnings:?}");
    assert_eq!(warnings[0].scope, "global rate_limit");
    assert!(warnings[0].message.contains("window_seconds"));

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn warns_per_scope_for_zero_window() -> TestResult {
    let path = tmp_path("rl-zero-window-route");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[[domains]]
host = "api.example.com"

[[domains.routes]]
prefix = "/admin"
backend = "backend:9000"

[domains.routes.security.rate_limit]
enabled = true
window_seconds = 0
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let warnings = rate_limit_warnings(&cfg);
    assert_eq!(warnings.len(), 1, "expected one finding, got: {warnings:?}");
    assert_eq!(warnings[0].scope, "route '/admin' in domain 'api.example.com' rate_limit");

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn silent_when_disabled_or_positive_window() -> TestResult {
    let path = tmp_path("rl-ok");
    // Disabled block with a zero window (inert), and an enabled block with a valid window.
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.rate_limit]
enabled = false
window_seconds = 0

[[domains]]
host = "api.example.com"
routes = [{ prefix = "/", backend = "backend:9000" }]

[domains.security.rate_limit]
enabled = true
window_seconds = 1
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    assert!(
        rate_limit_warnings(&cfg).is_empty(),
        "disabled or positive-window limiters must not warn: {:?}",
        rate_limit_warnings(&cfg)
    );

    let _ = fs::remove_file(&path);
    Ok(())
}
