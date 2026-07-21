//! Audit for enabled rate-limit blocks with a config that silently breaks the limiter.

use super::ConfigWarning;
use crate::config::{Config, LimitBy, RateLimitConfig};

/// Findings for one enabled rate-limit block. Disabled blocks build no limiter, so they are skipped.
///
/// Catches two silent footguns:
/// - `window_seconds == 0`: the limiter is built with `Duration::from_secs(0)` and cannot express a
///   rate.
/// - `limit_by = "header"` without a `limit_by_header`: at runtime the key extraction falls back to
///   the peer IP, silently limiting by IP instead of the intended header.
fn check_block(out: &mut Vec<ConfigWarning>, scope: &str, rl: &RateLimitConfig) {
    if !rl.enabled {
        return;
    }
    let mut push = |message: &str| {
        out.push(ConfigWarning { scope: scope.to_string(), message: message.to_string() });
    };
    if rl.window_seconds == 0 {
        push(
            "rate_limit is enabled but window_seconds is 0; the limiter cannot compute a rate \
             (window_seconds must be > 0)",
        );
    }
    let header_missing = rl
        .limit_by_header
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty();
    if rl.limit_by == LimitBy::Header && header_missing {
        push(
            "rate_limit uses limit_by = \"header\" but limit_by_header is empty; the limiter \
             silently falls back to limiting by client IP",
        );
    }
}

/// Non-fatal audit for enabled rate-limit blocks with a limiter-breaking config, flagged wherever a
/// block is configured (global, per-domain, per-route). Disabled blocks are ignored.
pub fn rate_limit_warnings(cfg: &Config) -> Vec<ConfigWarning> {
    let mut out = Vec::new();

    check_block(&mut out, "global rate_limit", &cfg.security.rate_limit);

    for domain in &cfg.domains {
        let label = domain.label();
        if let Some(rl) = domain.security.as_ref().and_then(|s| s.rate_limit.as_ref()) {
            check_block(&mut out, &format!("domain '{label}' rate_limit"), rl);
        }
        for route in &domain.routes {
            if let Some(rl) = route.security.as_ref().and_then(|s| s.rate_limit.as_ref()) {
                check_block(
                    &mut out,
                    &format!("route '{}' in domain '{label}' rate_limit", route.prefix),
                    rl,
                );
            }
        }
    }

    out
}
