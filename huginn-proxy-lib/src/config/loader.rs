use std::collections::HashSet;
use std::fs;
use std::path::Path;

use tracing::warn;

use crate::config::parser::ConfigFormat;
use crate::config::{Config, IpFilterConfig, IpFilterMode, RateLimitConfig, SecurityHeaders};
use crate::error::{ProxyError, Result};

pub fn load_from_path<P: AsRef<Path>>(p: P) -> Result<Config> {
    let path = p.as_ref();
    let format = ConfigFormat::from_path(path)?;

    let content = fs::read_to_string(path)
        .map_err(|e| ProxyError::Config(format!("Failed to read config file: {e}")))?;

    let mut cfg = format.parser().parse(&content)?;

    normalize_domain_hosts(&mut cfg);
    validate_config(&cfg)?;
    audit_security_overrides(&cfg);

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

/// A whole-block override that silently drops protection the parent scope had enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityOverrideWarning {
    /// Where the override lives, e.g. `domain 'api.example.com'` or `route '/admin' in domain '…'`.
    pub scope: String,
    /// Human-readable description of the dropped protection.
    pub message: String,
}

/// Non-fatal audit for the whole-block override footgun (pure; logged by `audit_security_overrides`).
///
/// Security policies (`rate_limit`, `ip_filter`, `headers`) replace the parent scope **entirely**
/// when set at a domain or route (no field merge). A partial override can therefore silently drop
/// protection the parent had enabled. Returns one finding per such case so callers can log them.
pub fn security_override_warnings(cfg: &Config) -> Vec<SecurityOverrideWarning> {
    let g = &cfg.security;
    let mut out = Vec::new();
    for domain in &cfg.domains {
        let label = domain.label();
        let dsec = domain.security.as_ref();

        if let Some(d) = dsec {
            let scope = format!("domain '{label}'");
            collect_dropped(
                &mut out,
                &scope,
                &g.rate_limit,
                d.rate_limit.as_ref(),
                &g.ip_filter,
                d.ip_filter.as_ref(),
                &g.headers,
                d.headers.as_ref(),
            );
        }

        for route in &domain.routes {
            let Some(r) = route.security.as_ref() else {
                continue;
            };
            let scope = format!("route '{}' in domain '{label}'", route.prefix);
            // Parent for a route is the domain-effective policy (domain.or(global)) per sub-block.
            let parent_rl = dsec
                .and_then(|s| s.rate_limit.as_ref())
                .unwrap_or(&g.rate_limit);
            let parent_ip = dsec
                .and_then(|s| s.ip_filter.as_ref())
                .unwrap_or(&g.ip_filter);
            let parent_hdr = dsec.and_then(|s| s.headers.as_ref()).unwrap_or(&g.headers);
            collect_dropped(
                &mut out,
                &scope,
                parent_rl,
                r.rate_limit.as_ref(),
                parent_ip,
                r.ip_filter.as_ref(),
                parent_hdr,
                r.headers.as_ref(),
            );
        }
    }
    out
}

/// Append a finding for each parent-enabled policy the override block turns off (whole-block).
#[allow(clippy::too_many_arguments)]
fn collect_dropped(
    out: &mut Vec<SecurityOverrideWarning>,
    scope: &str,
    parent_rl: &RateLimitConfig,
    over_rl: Option<&RateLimitConfig>,
    parent_ip: &IpFilterConfig,
    over_ip: Option<&IpFilterConfig>,
    parent_hdr: &SecurityHeaders,
    over_hdr: Option<&SecurityHeaders>,
) {
    let mut push =
        |message: String| out.push(SecurityOverrideWarning { scope: scope.to_string(), message });

    if let Some(over) = over_rl {
        if parent_rl.enabled && !over.enabled {
            push("rate_limit override disables the parent's enabled rate limit (whole block replaced, not merged)".to_string());
        }
    }
    if let Some(over) = over_ip {
        if parent_ip.mode != IpFilterMode::Disabled && over.mode == IpFilterMode::Disabled {
            push("ip_filter override disables the parent's active IP filter (whole block replaced, not merged)".to_string());
        }
    }
    if let Some(over) = over_hdr {
        let mut dropped: Vec<&str> = Vec::new();
        if parent_hdr.hsts.enabled && !over.hsts.enabled {
            dropped.push("HSTS");
        }
        if parent_hdr.csp.enabled && !over.csp.enabled {
            dropped.push("CSP");
        }
        if !parent_hdr.custom.is_empty() && over.custom.is_empty() {
            dropped.push("custom headers");
        }
        if !dropped.is_empty() {
            push(format!(
                "headers override drops parent-enabled protections [{}] (whole block replaced, not merged)",
                dropped.join(", ")
            ));
        }
    }
}

/// Log every [`security_override_warnings`] finding as a non-fatal `warn!`. Runs on boot,
/// `--validate`, and every hot reload; never aborts, since dropping a policy may be intended.
fn audit_security_overrides(cfg: &Config) {
    for w in security_override_warnings(cfg) {
        warn!(scope = %w.scope, "{}", w.message);
    }
}
