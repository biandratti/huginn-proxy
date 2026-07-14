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
