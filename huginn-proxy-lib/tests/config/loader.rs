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
listen = "127.0.0.1:0"
backends = [
  { address = "localhost:9000" }
]
"#;
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert_eq!(cfg.listen.to_string(), "127.0.0.1:0");
    assert_eq!(cfg.backends.len(), 1);
    assert!(cfg.routes.is_empty());
    assert!(cfg.tls.is_none());
    Ok(())
}

#[test]
fn loads_routes_and_tls() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("routes");

    let cert_path = tmp_path("server.crt");
    let key_path = tmp_path("server.key");
    fs::write(&cert_path, "dummy cert")?;
    fs::write(&key_path, "dummy key")?;

    let toml = format!(
        r#"
listen = "127.0.0.1:0"
backends = [
  {{ address = "backend-a:9000" }},
  {{ address = "backend-b:9000" }}
]
routes = [
  {{ prefix = "/api", backend = "backend-a:9000" }},
  {{ prefix = "/", backend = "backend-b:9000" }}
]

[tls]
cert_path = "{}"
key_path  = "{}"
alpn = ["h2"]
"#,
        cert_path.display(),
        key_path.display()
    );
    fs::write(&path, toml)?;

    let cfg = load_from_path(&path)?;
    assert_eq!(cfg.backends.len(), 2);
    assert_eq!(cfg.routes.len(), 2);
    let tls = cfg.tls.ok_or("tls missing")?;
    assert_eq!(tls.cert_path, cert_path.display().to_string());
    assert_eq!(tls.alpn, vec!["h2"]);

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);
    Ok(())
}
