use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const CONFIG: &str = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]
headers = { request = { add = [
  { name = "Authorization", value = "cli-secret" }
] } }
"#;

// Same header added twice → a duplicate-header warning (non-fatal).
const CONFIG_WITH_WARNING: &str = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]
headers = { request = { add = [
  { name = "X-Foo", value = "a" },
  { name = "x-foo", value = "b" }
] } }
"#;

fn temp_config(name: &str, contents: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    let path = std::env::temp_dir().join(format!("huginn-cli-{nanos}-{name}.toml"));
    fs::write(&path, contents)?;
    Ok(path)
}

fn run(args: &[&str]) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_huginn-proxy"))
        .args(args)
        .output()
}

#[test]
fn validate_keeps_existing_output() -> TestResult {
    let path = temp_config("validate", CONFIG)?;
    let path_arg = path.to_string_lossy().into_owned();
    let output = run(&["--validate", &path_arg])?;
    let _ = fs::remove_file(path);

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout)?, format!("Config OK: {path_arg}\n"));
    Ok(())
}

#[test]
fn validate_reports_warning_count_but_exits_zero_by_default() -> TestResult {
    let path = temp_config("validate-warn", CONFIG_WITH_WARNING)?;
    let path_arg = path.to_string_lossy().into_owned();
    let output = run(&["--validate", &path_arg])?;
    let _ = fs::remove_file(path);

    assert!(output.status.success(), "warnings must not fail without --strict");
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(&format!("Config OK: {path_arg}")), "stdout: {stdout}");
    assert!(stdout.contains("warning(s) found"), "stdout: {stdout}");
    Ok(())
}

#[test]
fn validate_strict_fails_on_warnings() -> TestResult {
    let path = temp_config("validate-strict-warn", CONFIG_WITH_WARNING)?;
    let path_arg = path.to_string_lossy().into_owned();
    let output = run(&["--validate", "--strict", &path_arg])?;
    let _ = fs::remove_file(path);

    assert!(!output.status.success(), "--strict must fail when warnings exist");
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("strict validation failed"), "stderr: {stderr}");
    Ok(())
}

#[test]
fn validate_strict_fails_on_proxy_protocol_trust_gap() -> TestResult {
    // proxy_protocol=require with no trusted_proxies drops every connection; surfaced in --validate.
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"], proxy_protocol = { mode = "require" } }
backends = [{ address = "backend:9000" }]
"#;
    let path = temp_config("validate-pp-gap", toml)?;
    let path_arg = path.to_string_lossy().into_owned();
    let output = run(&["--validate", "--strict", &path_arg])?;
    let _ = fs::remove_file(path);

    assert!(!output.status.success(), "proxy_protocol trust gap must fail --strict");
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("strict validation failed"), "stderr: {stderr}");
    Ok(())
}

#[test]
fn validate_strict_passes_on_clean_config() -> TestResult {
    let path = temp_config("validate-strict-clean", CONFIG)?;
    let path_arg = path.to_string_lossy().into_owned();
    let output = run(&["--validate", "--strict", &path_arg])?;
    let _ = fs::remove_file(path);

    assert!(output.status.success(), "clean config must pass --strict");
    assert_eq!(String::from_utf8(output.stdout)?, format!("Config OK: {path_arg}\n"));
    Ok(())
}

#[test]
fn print_effective_config_implies_validation_and_outputs_redacted_json() -> TestResult {
    let path = temp_config("effective", CONFIG)?;
    let path_arg = path.to_string_lossy().into_owned();
    let output = run(&["--print-effective-config", &path_arg])?;
    let _ = fs::remove_file(path);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    let value: serde_json::Value = serde_json::from_str(&stdout)?;

    assert_eq!(value["static"]["listen"]["addrs"][0], "127.0.0.1:0");
    assert_eq!(value["dynamic"]["headers"]["request"]["add"][0]["value"], "<redacted>");
    assert!(!stdout.contains("cli-secret"));
    assert!(!stdout.contains("Config OK"));
    Ok(())
}
