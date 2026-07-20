use std::fs;

use huginn_proxy_lib::config::load_from_path;

use super::tmp_path;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const BASE: &str = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [
  { address = "localhost:9000" }
]
"#;

#[test]
fn reload_defaults_to_watch_on_and_60s_debounce() -> TestResult {
    let path = tmp_path("reload-default");
    fs::write(&path, BASE)?;

    let cfg = load_from_path(&path)?;
    assert!(cfg.reload.watch);
    assert_eq!(cfg.reload.debounce_secs, 60);
    Ok(())
}

#[test]
fn reload_parses_explicit_values() -> TestResult {
    let path = tmp_path("reload-explicit");
    let toml = format!("{BASE}\n[reload]\nwatch = false\ndebounce_secs = 5\n");
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert!(!cfg.reload.watch);
    assert_eq!(cfg.reload.debounce_secs, 5);
    Ok(())
}

#[test]
fn reload_rejects_unknown_field() -> TestResult {
    let path = tmp_path("reload-unknown");
    let toml = format!("{BASE}\n[reload]\nwatch = true\nbogus = 1\n");
    fs::write(&path, toml)?;

    assert!(load_from_path(&path).is_err());
    Ok(())
}
