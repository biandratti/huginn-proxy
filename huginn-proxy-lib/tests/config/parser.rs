use std::path::Path;

use huginn_proxy_lib::config::parser::{ConfigFormat, TomlParser, YamlParser};
use huginn_proxy_lib::config::ConfigParser;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn detects_toml_extension() -> TestResult {
    assert_eq!(ConfigFormat::from_path(Path::new("config.toml"))?, ConfigFormat::Toml);
    Ok(())
}

#[test]
fn detects_yaml_extension() -> TestResult {
    assert_eq!(ConfigFormat::from_path(Path::new("config.yaml"))?, ConfigFormat::Yaml);
    Ok(())
}

#[test]
fn detects_yml_extension() -> TestResult {
    assert_eq!(ConfigFormat::from_path(Path::new("config.yml"))?, ConfigFormat::Yaml);
    Ok(())
}

#[test]
fn rejects_unknown_extension() -> TestResult {
    let Err(err) = ConfigFormat::from_path(Path::new("config.json")) else {
        return Err("expected Err for .json extension but got Ok".into());
    };
    let msg = err.to_string();
    assert!(msg.contains(".json"), "error should mention the bad extension: {msg}");
    assert!(msg.contains(".toml"), "error should hint at valid extensions: {msg}");
    Ok(())
}

#[test]
fn rejects_missing_extension() -> TestResult {
    let Err(err) = ConfigFormat::from_path(Path::new("config")) else {
        return Err("expected Err for path without extension but got Ok".into());
    };
    let msg = err.to_string();
    assert!(msg.contains("no extension"), "error should mention missing extension: {msg}");
    Ok(())
}

#[test]
fn toml_parser_parses_minimal_config() -> TestResult {
    let input = r#"
        listen = { addrs = ["127.0.0.1:0"] }
        backends = [{ address = "localhost:3000" }]
    "#;
    let cfg = TomlParser.parse(input)?;
    assert_eq!(cfg.backends.len(), 1);
    assert_eq!(cfg.backends[0].address, "localhost:3000");
    Ok(())
}

#[test]
fn toml_parser_returns_error_on_invalid_syntax() -> TestResult {
    let Err(err) = TomlParser.parse("this is not toml :::") else {
        return Err("expected parse error but TOML parser succeeded".into());
    };
    assert!(err.to_string().contains("TOML parse error"));
    Ok(())
}

#[test]
fn yaml_parser_parses_minimal_config() -> TestResult {
    let input = r#"
listen:
  addrs:
    - "127.0.0.1:0"
backends:
  - address: "localhost:3000"
"#;
    let cfg = YamlParser.parse(input)?;
    assert_eq!(cfg.backends.len(), 1);
    assert_eq!(cfg.backends[0].address, "localhost:3000");
    Ok(())
}

#[test]
fn yaml_parser_returns_error_on_invalid_syntax() -> TestResult {
    let Err(err) = YamlParser.parse("key: [unclosed") else {
        return Err("expected parse error but YAML parser succeeded".into());
    };
    assert!(err.to_string().contains("YAML parse error"));
    Ok(())
}

#[test]
fn toml_and_yaml_produce_equivalent_backends() -> TestResult {
    let toml_input = r#"
        listen = { addrs = ["0.0.0.0:7000"] }
        backends = [
          { address = "backend-a:9000", http_version = "http11" },
          { address = "backend-b:9000" },
        ]
    "#;
    let yaml_input = r#"
listen:
  addrs:
    - "0.0.0.0:7000"
backends:
  - address: "backend-a:9000"
    http_version: http11
  - address: "backend-b:9000"
"#;
    let toml_cfg = TomlParser.parse(toml_input)?;
    let yaml_cfg = YamlParser.parse(yaml_input)?;

    assert_eq!(toml_cfg.backends.len(), yaml_cfg.backends.len());
    for (t, y) in toml_cfg.backends.iter().zip(yaml_cfg.backends.iter()) {
        assert_eq!(t.address, y.address);
        assert_eq!(t.http_version, y.http_version);
    }
    Ok(())
}
