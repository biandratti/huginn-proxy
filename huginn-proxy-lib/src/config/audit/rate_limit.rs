//! Audit for rate-limit blocks that can never compute a valid rate.

use super::ConfigWarning;
use crate::config::{Config, RateLimitConfig};

/// Push a finding when an enabled rate limit has a zero-length window. The limiter is built with
/// `Duration::from_secs(window_seconds)`, so a `0` window cannot express any rate.
fn check_window(out: &mut Vec<ConfigWarning>, scope: String, rl: &RateLimitConfig) {
    if rl.enabled && rl.window_seconds == 0 {
        out.push(ConfigWarning {
            scope,
            message: "rate_limit is enabled but window_seconds is 0; the limiter cannot compute a \
                      rate (window_seconds must be > 0)"
                .to_string(),
        });
    }
}

/// Non-fatal audit for rate-limit blocks with a zero `window_seconds`.
///
/// A `window_seconds` of 0 is never valid for an enabled limiter, so it is flagged wherever a
/// rate_limit block is configured (global, per-domain, per-route). Disabled blocks are ignored
/// since no limiter is built.
pub fn rate_limit_warnings(cfg: &Config) -> Vec<ConfigWarning> {
    let mut out = Vec::new();

    check_window(&mut out, "global rate_limit".to_string(), &cfg.security.rate_limit);

    for domain in &cfg.domains {
        let label = domain.label();
        if let Some(rl) = domain.security.as_ref().and_then(|s| s.rate_limit.as_ref()) {
            check_window(&mut out, format!("domain '{label}' rate_limit"), rl);
        }
        for route in &domain.routes {
            if let Some(rl) = route.security.as_ref().and_then(|s| s.rate_limit.as_ref()) {
                check_window(
                    &mut out,
                    format!("route '{}' in domain '{label}' rate_limit", route.prefix),
                    rl,
                );
            }
        }
    }

    out
}
