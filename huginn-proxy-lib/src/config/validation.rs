//! Non-fatal configuration audits.
//!
//! These checks never abort loading: the config is valid but likely a mistake. Findings are
//! returned as [`ConfigWarning`]s by pure functions (so they are unit-testable) and logged via the
//! `audit_*` helpers on boot, `--validate`, and every hot reload.

use std::collections::HashSet;

use tracing::warn;

use crate::config::{
    Config, CustomHeader, HeaderManipulation, IpFilterConfig, IpFilterMode, RateLimitConfig,
    SecurityHeaders,
};

/// A non-fatal configuration finding: the config is valid but likely a mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// Where the issue lives, e.g. `domain 'api.example.com' headers`.
    pub scope: String,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Case-insensitive duplicate header names within a single list, in first-seen order and
/// reported once each. Header names are case-insensitive (RFC 9110 §5.1).
fn duplicate_header_names(headers: &[CustomHeader]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut reported: HashSet<String> = HashSet::new();
    let mut dupes: Vec<String> = Vec::new();
    for header in headers {
        let key = header.name.to_ascii_lowercase();
        if !seen.insert(key.clone()) && reported.insert(key) {
            dupes.push(header.name.clone());
        }
    }
    dupes
}

/// Findings for one request/response header-manipulation block: names added more than once
/// (silently last-wins at runtime) and names both added and removed (contradictory).
fn collect_header_manipulation_warnings(
    out: &mut Vec<ConfigWarning>,
    scope: &str,
    manip: &HeaderManipulation,
) {
    for (direction, group) in [("request", &manip.request), ("response", &manip.response)] {
        for name in duplicate_header_names(&group.add) {
            out.push(ConfigWarning {
                scope: scope.to_string(),
                message: format!(
                    "{direction} header '{name}' is added more than once; only the last value applies"
                ),
            });
        }
        let removed: HashSet<String> = group
            .remove
            .iter()
            .map(|n| n.to_ascii_lowercase())
            .collect();
        let mut conflicted: HashSet<String> = HashSet::new();
        for header in &group.add {
            let key = header.name.to_ascii_lowercase();
            if removed.contains(&key) && conflicted.insert(key) {
                out.push(ConfigWarning {
                    scope: scope.to_string(),
                    message: format!(
                        "{direction} header '{}' is both added and removed",
                        header.name
                    ),
                });
            }
        }
    }
}

/// Findings for one `security.headers.custom` list: names listed more than once.
fn collect_custom_header_warnings(
    out: &mut Vec<ConfigWarning>,
    scope: &str,
    headers: &SecurityHeaders,
) {
    for name in duplicate_header_names(&headers.custom) {
        out.push(ConfigWarning {
            scope: scope.to_string(),
            message: format!(
                "custom security header '{name}' is listed more than once; only the last value applies"
            ),
        });
    }
}

/// Non-fatal audit for duplicate/contradictory header configuration (pure; logged by
/// [`audit_header_config`]).
///
/// Because header add lists are applied with last-wins semantics (`HeaderMap::insert`), a repeated
/// name is dead config rather than a multi-value header. Duplicates are reported per scope and per
/// direction independently; overriding the same header across scopes (global → domain → route) is
/// intentional and never reported.
pub fn header_config_warnings(cfg: &Config) -> Vec<ConfigWarning> {
    let mut out = Vec::new();

    if let Some(manip) = &cfg.headers {
        collect_header_manipulation_warnings(&mut out, "global headers", manip);
    }
    collect_custom_header_warnings(&mut out, "global security headers", &cfg.security.headers);

    for domain in &cfg.domains {
        let label = domain.label();
        if let Some(manip) = &domain.headers {
            collect_header_manipulation_warnings(
                &mut out,
                &format!("domain '{label}' headers"),
                manip,
            );
        }
        if let Some(sec) = domain.security.as_ref().and_then(|s| s.headers.as_ref()) {
            collect_custom_header_warnings(
                &mut out,
                &format!("domain '{label}' security headers"),
                sec,
            );
        }
        for route in &domain.routes {
            if let Some(manip) = &route.headers {
                collect_header_manipulation_warnings(
                    &mut out,
                    &format!("route '{}' in domain '{label}' headers", route.prefix),
                    manip,
                );
            }
            if let Some(sec) = route.security.as_ref().and_then(|s| s.headers.as_ref()) {
                collect_custom_header_warnings(
                    &mut out,
                    &format!("route '{}' in domain '{label}' security headers", route.prefix),
                    sec,
                );
            }
        }
    }

    out
}

/// Log every [`header_config_warnings`] finding as a non-fatal `warn!`. Runs on boot,
/// `--validate`, and every hot reload; never aborts, since the config still loads.
pub(crate) fn audit_header_config(cfg: &Config) {
    for w in header_config_warnings(cfg) {
        warn!(scope = %w.scope, "{}", w.message);
    }
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
pub(crate) fn audit_security_overrides(cfg: &Config) {
    for w in security_override_warnings(cfg) {
        warn!(scope = %w.scope, "{}", w.message);
    }
}
