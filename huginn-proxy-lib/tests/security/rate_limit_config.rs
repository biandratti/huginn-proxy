use huginn_proxy_lib::config::RateLimitConfig;
use ipnet::IpNet;

#[test]
fn default_trusted_proxies_is_empty() {
    assert!(RateLimitConfig::default().trusted_proxies.is_empty());
}

#[test]
fn deserialize_trusted_proxies_toml() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let toml = r#"
        trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
    "#;
    let config: RateLimitConfig = toml::from_str(toml)?;
    assert_eq!(config.trusted_proxies.len(), 2);
    assert_eq!(config.trusted_proxies[0], "10.0.0.0/8".parse::<IpNet>()?);
    assert_eq!(config.trusted_proxies[1], "172.16.0.0/12".parse::<IpNet>()?);
    Ok(())
}

#[test]
fn deserialize_invalid_cidr_errors() {
    let toml = r#"trusted_proxies = ["not-a-cidr"]"#;
    assert!(toml::from_str::<RateLimitConfig>(toml).is_err());
}
