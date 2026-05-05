use std::net::IpAddr;

use crate::config::{IpFilterConfig, IpFilterMode};

/// Check if an IP address is allowed based on the filter configuration
///
/// Returns `true` if the IP should be allowed, `false` if it should be blocked.
///
/// # Logic:
/// - If mode is `IpFilterMode::Disabled`: always allow
/// - If mode is `IpFilterMode::Allowlist`: allow only if IP matches allowlist
/// - If mode is `IpFilterMode::Denylist`: block if IP matches denylist
pub fn is_ip_allowed(ip: IpAddr, config: &IpFilterConfig) -> bool {
    match config.mode {
        IpFilterMode::Disabled => true,
        IpFilterMode::Allowlist => {
            // Allow only if IP matches any entry in allowlist
            if config.allowlist.is_empty() {
                // Empty allowlist = deny all
                return false;
            }
            config.allowlist.iter().any(|net| net.contains(&ip))
        }
        IpFilterMode::Denylist => {
            // Block if IP matches any entry in denylist
            if config.denylist.is_empty() {
                // Empty denylist = allow all
                return true;
            }
            !config.denylist.iter().any(|net| net.contains(&ip))
        }
    }
}
