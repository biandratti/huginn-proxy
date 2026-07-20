//! Audit for whole-block security overrides that silently drop parent protection.

use super::ConfigWarning;
use crate::config::{Config, IpFilterConfig, IpFilterMode, RateLimitConfig, SecurityHeaders};

/// Non-fatal audit for the whole-block override footgun.
///
/// Security policies (`rate_limit`, `ip_filter`, `headers`) replace the parent scope **entirely**
/// when set at a domain or route (no field merge). A partial override can therefore silently drop
/// protection the parent had enabled. Returns one finding per such case so callers can log them.
pub fn security_override_warnings(cfg: &Config) -> Vec<ConfigWarning> {
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
    out: &mut Vec<ConfigWarning>,
    scope: &str,
    parent_rl: &RateLimitConfig,
    over_rl: Option<&RateLimitConfig>,
    parent_ip: &IpFilterConfig,
    over_ip: Option<&IpFilterConfig>,
    parent_hdr: &SecurityHeaders,
    over_hdr: Option<&SecurityHeaders>,
) {
    let mut push = |message: String| out.push(ConfigWarning { scope: scope.to_string(), message });

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
