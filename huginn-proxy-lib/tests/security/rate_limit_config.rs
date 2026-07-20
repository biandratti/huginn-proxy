use huginn_proxy_lib::config::SecurityConfig;
use ipnet::IpNet;

#[test]
fn default_trusted_proxies_is_empty() {
    let tp = SecurityConfig::default().trusted_proxies;
    assert!(tp.cidrs.is_empty());
    assert!(!tp.insecure);
}

#[test]
fn deserialize_trusted_proxies_toml() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
        [trusted_proxies]
        cidrs = ["10.0.0.0/8", "172.16.0.0/12"]
    "#;
    let config: SecurityConfig = toml::from_str(toml)?;
    assert_eq!(config.trusted_proxies.cidrs.len(), 2);
    assert_eq!(config.trusted_proxies.cidrs[0], "10.0.0.0/8".parse::<IpNet>()?);
    assert_eq!(config.trusted_proxies.cidrs[1], "172.16.0.0/12".parse::<IpNet>()?);
    assert!(!config.trusted_proxies.insecure);
    Ok(())
}

#[test]
fn deserialize_trusted_proxies_insecure() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
        [trusted_proxies]
        insecure = true
    "#;
    let config: SecurityConfig = toml::from_str(toml)?;
    assert!(config.trusted_proxies.cidrs.is_empty());
    assert!(config.trusted_proxies.insecure);
    Ok(())
}

#[test]
fn deserialize_invalid_cidr_errors() {
    let toml = r#"
        [trusted_proxies]
        cidrs = ["not-a-cidr"]
    "#;
    assert!(toml::from_str::<SecurityConfig>(toml).is_err());
}

#[test]
fn deserialize_unknown_field_errors() {
    let toml = r#"
        [trusted_proxies]
        cidrs = ["10.0.0.0/8"]
        allow_trust_all = true
    "#;
    assert!(toml::from_str::<SecurityConfig>(toml).is_err());
}
