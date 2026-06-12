use std::sync::Arc;

use ipnet::IpNet;

use crate::config::{HeaderManipulation, IpFilterConfig, RateLimitConfig, SecurityHeaders};
use crate::security::RateLimitManager;

/// Security-related context for request handling
#[derive(Clone)]
pub struct SecurityContext {
    pub headers: SecurityHeaders,
    pub ip_filter: IpFilterConfig,
    pub rate_limit_config: RateLimitConfig,
    pub rate_limit_manager: Option<Arc<RateLimitManager>>,
    pub global_header_manipulation: Option<HeaderManipulation>,
    /// Global trusted reverse-proxy CIDRs used to resolve the real client IP from XFF.
    pub trusted_proxies: Vec<IpNet>,
}

impl SecurityContext {
    pub fn new(
        headers: SecurityHeaders,
        ip_filter: IpFilterConfig,
        rate_limit_config: RateLimitConfig,
        rate_limit_manager: Option<Arc<RateLimitManager>>,
        global_header_manipulation: Option<HeaderManipulation>,
        trusted_proxies: Vec<IpNet>,
    ) -> Self {
        Self {
            headers,
            ip_filter,
            rate_limit_config,
            rate_limit_manager,
            global_header_manipulation,
            trusted_proxies,
        }
    }
}
