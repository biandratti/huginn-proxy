//! Audit for duplicate / contradictory header configuration.

use std::collections::HashSet;

use super::ConfigWarning;
use crate::config::{Config, CustomHeader, HeaderManipulation, SecurityHeaders};

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

/// Non-fatal audit for duplicate/contradictory header configuration.
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
