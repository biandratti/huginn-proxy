//! Non-fatal configuration audits.
//!
//! These checks never abort loading: the config is valid but likely a mistake. Each submodule
//! exposes a **pure** function returning structured findings (so it is unit-testable); [`run`]
//! owns the side effect of logging them as `warn!`. Audits run on boot, `--validate`, and every
//! hot reload.
//!
//! | Submodule            | Pure entry point             | Detects                                   |
//! |----------------------|------------------------------|-------------------------------------------|
//! | [`headers`]          | [`header_config_warnings`]   | duplicate / contradictory header config   |
//! | [`security_overrides`] | [`security_override_warnings`] | whole-block overrides dropping protection |
//! | [`trusted_proxies`]  | [`trusted_proxies_warnings`] | over-broad `trusted_proxies` ranges       |

mod headers;
mod security_overrides;
mod trusted_proxies;

use tracing::warn;

pub use headers::header_config_warnings;
pub use security_overrides::{security_override_warnings, SecurityOverrideWarning};
pub use trusted_proxies::trusted_proxies_warnings;

use crate::config::Config;

/// A non-fatal configuration finding: the config is valid but likely a mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// Where the issue lives, e.g. `domain 'api.example.com' headers`.
    pub scope: String,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Run every non-fatal config audit and log each finding as a `warn!`. Runs on boot, `--validate`,
/// and every hot reload; never aborts, since the config still loads.
pub(crate) fn run(cfg: &Config) {
    for w in header_config_warnings(cfg) {
        warn!(scope = %w.scope, "{}", w.message);
    }
    for w in security_override_warnings(cfg) {
        warn!(scope = %w.scope, "{}", w.message);
    }
    for w in trusted_proxies_warnings(cfg) {
        warn!(scope = %w.scope, "{}", w.message);
    }
}
