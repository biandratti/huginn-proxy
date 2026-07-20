use std::fs;

use huginn_proxy_lib::config::{load_from_path, trusted_proxies_warnings};

use crate::config::tmp_path;

#[test]
fn trusted_proxies_audit_warns_on_trust_all_and_broad_range(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("tp-broad");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.trusted_proxies]
# 0.0.0.0/0 trusts everyone; 11.0.0.0/6 is broader than /8 (public); ::/0 trusts all IPv6.
cidrs = ["0.0.0.0/0", "11.0.0.0/6", "::/0"]
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let warnings = trusted_proxies_warnings(&cfg);
    assert_eq!(warnings.len(), 3, "expected 3 findings, got: {warnings:?}");
    assert!(warnings.iter().all(|w| w.scope == "trusted_proxies"));
    assert_eq!(
        warnings
            .iter()
            .filter(|w| w.message.contains("trusts every IP address"))
            .count(),
        2,
        "0.0.0.0/0 and ::/0 are both trust-all: {warnings:?}"
    );
    assert!(warnings
        .iter()
        .any(|w| w.message.contains("very large address range")));

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn insecure_opt_in_silences_trust_all_warning(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("tp-optin");
    // insecure acknowledges the /0 footgun, but a broad non-/0 range still warns.
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.trusted_proxies]
insecure = true
cidrs = ["0.0.0.0/0", "11.0.0.0/6"]
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    let warnings = trusted_proxies_warnings(&cfg);
    assert_eq!(warnings.len(), 1, "trust-all suppressed, broad range still warns: {warnings:?}");
    assert!(warnings[0].message.contains("very large address range"));
    assert!(
        !warnings
            .iter()
            .any(|w| w.message.contains("trusts every IP address")),
        "trust-all must be suppressed by opt-in: {warnings:?}"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn trusted_proxies_audit_silent_on_private_ranges(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = tmp_path("tp-private");
    let toml = r#"
listen = { addrs = ["127.0.0.1:0"] }
backends = [{ address = "backend:9000" }]

[security.trusted_proxies]
cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "::1/128"]
"#;
    fs::write(&path, toml)?;
    let cfg = load_from_path(&path)?;

    assert!(
        trusted_proxies_warnings(&cfg).is_empty(),
        "standard private/reserved ranges must not warn: {:?}",
        trusted_proxies_warnings(&cfg)
    );

    let _ = fs::remove_file(&path);
    Ok(())
}
