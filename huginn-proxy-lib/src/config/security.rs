use ipnet::IpNet;
use serde::Deserialize;

use super::headers::CustomHeader;

/// Security configuration
#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    /// Maximum number of concurrent connections allowed
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Security headers configuration
    #[serde(default)]
    pub headers: SecurityHeaders,
    /// IP filtering (ACL) configuration
    #[serde(default)]
    pub ip_filter: IpFilterConfig,
    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            headers: SecurityHeaders::default(),
            ip_filter: IpFilterConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

fn default_max_connections() -> usize {
    512
}

/// Security headers configuration
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
pub struct SecurityHeaders {
    /// Custom headers to add to all responses
    #[serde(default)]
    pub custom: Vec<CustomHeader>,
    /// HSTS (HTTP Strict Transport Security) configuration
    #[serde(default)]
    pub hsts: HstsConfig,
    /// CSP (Content Security Policy) configuration
    #[serde(default)]
    pub csp: CspConfig,
}

/// HSTS (HTTP Strict Transport Security) configuration
///
/// Reference: RFC 6797 - https://tools.ietf.org/html/rfc6797
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct HstsConfig {
    /// Enable HSTS (only applies to HTTPS connections)
    #[serde(default)]
    pub enabled: bool,
    /// Max age in seconds (RFC 6797 requirement)
    ///
    /// Common values:
    /// - 31536000 (1 year) - Recommended for production
    /// - 63072000 (2 years) - Very secure
    /// - 2592000 (30 days) - Minimum recommended
    /// - 300 (5 minutes) - Testing only
    ///
    /// Default: 31536000 (1 year)
    #[serde(default = "default_hsts_max_age")]
    pub max_age: u64,
    /// Include subdomains in HSTS policy (includeSubDomains directive)
    #[serde(default)]
    pub include_subdomains: bool,
    /// Add preload directive for HSTS preload list submission
    ///
    /// Warning: Only enable if you plan to submit to https://hstspreload.org/
    /// This is a permanent commitment and cannot be easily undone.
    #[serde(default)]
    pub preload: bool,
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: default_hsts_max_age(),
            include_subdomains: false,
            preload: false,
        }
    }
}

fn default_hsts_max_age() -> u64 {
    31536000 // 1 year
}

/// CSP (Content Security Policy) configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct CspConfig {
    /// Enable CSP
    #[serde(default)]
    pub enabled: bool,
    /// CSP policy string
    #[serde(default = "default_csp_policy")]
    pub policy: String,
}

impl Default for CspConfig {
    fn default() -> Self {
        Self { enabled: false, policy: default_csp_policy() }
    }
}

fn default_csp_policy() -> String {
    "default-src 'self'".to_string()
}

/// IP filtering mode
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpFilterMode {
    /// IP filtering is disabled (allow all)
    #[default]
    Disabled,
    /// Only allow IPs in the allowlist
    Allowlist,
    /// Block IPs in the denylist
    Denylist,
}

/// IP filtering (ACL) configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct IpFilterConfig {
    /// Filtering mode
    #[serde(default)]
    pub mode: IpFilterMode,
    /// Allowlist: Only these IPs/networks are allowed (when mode = "allowlist")
    /// Supports CIDR notation: ["127.0.0.1/32", "192.168.1.0/24", "::1/128"]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ip_networks")]
    pub allowlist: Vec<IpNet>,
    /// Denylist: These IPs/networks are blocked (when mode = "denylist")
    /// Supports CIDR notation: ["10.0.0.0/8", "172.16.0.0/12"]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ip_networks")]
    pub denylist: Vec<IpNet>,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self { mode: IpFilterMode::Disabled, allowlist: vec![], denylist: vec![] }
    }
}

/// Custom deserializer for IP networks that handles parsing errors gracefully
fn deserialize_ip_networks<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    let mut networks = Vec::new();

    for s in strings {
        match s.parse::<IpNet>() {
            Ok(net) => networks.push(net),
            Err(e) => {
                return Err(serde::de::Error::custom(format!("Invalid IP network '{}': {}", s, e)));
            }
        }
    }

    Ok(networks)
}

/// Rate limiting configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    /// Default: false
    #[serde(default)]
    pub enabled: bool,
    /// Maximum requests per second
    /// Default: 1000
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
    /// Burst size (maximum requests in a single window)
    /// Default: 2000 (2x requests_per_second)
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Time window in seconds
    /// Default: 1
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    /// Key extraction strategy
    /// Default: "ip"
    #[serde(default = "default_limit_by")]
    pub limit_by: LimitBy,
    /// Custom header name for "header" limit_by mode
    /// Required when limit_by = "header"
    pub limit_by_header: Option<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: default_requests_per_second(),
            burst: default_burst(),
            window_seconds: default_window_seconds(),
            limit_by: default_limit_by(),
            limit_by_header: None,
        }
    }
}

/// Per-route rate limiting configuration
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RouteRateLimitConfig {
    /// Enable rate limiting for this route
    /// If not specified, inherits from global config
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Maximum requests per second for this route
    /// If not specified, uses global config
    pub requests_per_second: Option<u32>,
    /// Burst size for this route
    /// If not specified, uses global config
    pub burst: Option<u32>,
    /// Key extraction strategy for this route
    /// If not specified, uses global config
    pub limit_by: Option<LimitBy>,
    /// Custom header name for "header" limit_by mode
    /// If not specified, uses global config
    pub limit_by_header: Option<String>,
}

/// Rate limiting key extraction strategy
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LimitBy {
    /// Rate limit by client IP address
    /// Extracts IP from X-Forwarded-For or connection IP
    Ip,
    /// Rate limit by custom header value
    /// Requires limit_by_header to be specified
    Header,
    /// Rate limit by route path
    /// All clients share the same limit for a route
    Route,
    /// Rate limit by combination of IP and route
    /// Provides per-IP limits that are also route-specific
    Combined,
}

fn default_requests_per_second() -> u32 {
    1000
}

fn default_burst() -> u32 {
    2000
}

fn default_window_seconds() -> u64 {
    1
}

fn default_limit_by() -> LimitBy {
    LimitBy::Ip
}
