use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::config::audit;
use crate::config::parser::ConfigFormat;
use crate::config::Config;
use crate::error::{ProxyError, Result};

pub fn load_from_path<P: AsRef<Path>>(p: P) -> Result<Config> {
    let path = p.as_ref();
    let format = ConfigFormat::from_path(path)?;

    let content = fs::read_to_string(path)
        .map_err(|e| ProxyError::Config(format!("Failed to read config file: {e}")))?;

    let mut cfg = format.parser().parse(&content)?;

    normalize_domain_hosts(&mut cfg);
    validate_config(&cfg)?;
    audit::run(&cfg);

    Ok(cfg)
}

/// Lowercase every domain `host`. DNS names and the HTTP `Host` header are
/// case-insensitive (RFC 4343 / RFC 7230); the request side is lowercased in
/// `extract_request_host`, so config and request hosts compare consistently.
fn normalize_domain_hosts(cfg: &mut Config) {
    for domain in &mut cfg.domains {
        if let Some(host) = domain.host.as_mut() {
            host.make_ascii_lowercase();
        }
    }
}

/// Reject duplicate hosts and more than one catch-all (host-less) domain, which
/// would make domain selection and cert resolution disagree (routing keeps the
/// first match; the cert resolver keeps the last).
fn validate_unique_hosts(cfg: &Config) -> Result<()> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut has_catch_all = false;
    for domain in &cfg.domains {
        match domain.host.as_deref() {
            None => {
                if has_catch_all {
                    return Err(ProxyError::Config(
                        "Multiple catch-all domains (entries with no `host`); \
                         at most one is allowed"
                            .to_string(),
                    ));
                }
                has_catch_all = true;
            }
            Some(host) => {
                if !seen.insert(host) {
                    return Err(ProxyError::Config(format!("Duplicate domain host '{host}'")));
                }
            }
        }
    }
    Ok(())
}

fn validate_config(cfg: &Config) -> Result<()> {
    validate_unique_hosts(cfg)?;

    for domain in &cfg.domains {
        let host = domain.label();
        match (&domain.cert_path, &domain.key_path) {
            (Some(cert), Some(key)) => {
                if !Path::new(cert).exists() {
                    return Err(ProxyError::Config(format!(
                        "Domain '{host}': certificate file not found: {cert}"
                    )));
                }
                if !Path::new(key).exists() {
                    return Err(ProxyError::Config(format!(
                        "Domain '{host}': key file not found: {key}"
                    )));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ProxyError::Config(format!(
                    "Domain '{host}': cert_path and key_path must both be set or both omitted"
                )));
            }
        }
    }

    cfg.validate_cross_refs()?;

    Ok(())
}
