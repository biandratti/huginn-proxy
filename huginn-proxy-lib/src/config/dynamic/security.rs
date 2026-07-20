use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::headers::CustomHeader;
use crate::config::Secret;

/// Security configuration (used for TOML deserialization via Config)
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Maximum number of concurrent connections allowed (static requires restart to change)
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
    /// Trusted reverse-proxy configuration for client-IP resolution (`[security.trusted_proxies]`).
    ///
    /// A property of the network topology (which load balancers sit in front), not of a
    /// route, so it is configured once globally and is **not** overridable per domain/route.
    #[serde(default)]
    pub trusted_proxies: TrustedProxiesConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            headers: SecurityHeaders::default(),
            ip_filter: IpFilterConfig::default(),
            rate_limit: RateLimitConfig::default(),
            trusted_proxies: TrustedProxiesConfig::default(),
        }
    }
}

/// Trusted reverse-proxy configuration (`[security.trusted_proxies]`).
///
/// Defines which immediate TCP peers are allowed to declare the real client address via
/// `X-Forwarded-For` (rate-limit client IP) and the PROXY protocol header. This is the trust
/// boundary against source-IP spoofing: an untrusted peer's `X-Forwarded-For`/PROXY header is
/// ignored, so only the non-forgeable TCP peer IP is used.
///
/// When a peer is trusted, `X-Forwarded-For` is walked right-to-left and the first IP not in
/// `cidrs` is used as the real client IP. Consumed by rate limiting (`limit_by = "ip" | "combined"`)
/// and PROXY protocol handling.
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct TrustedProxiesConfig {
    /// Trusted reverse-proxy CIDRs. Accepts CIDR notation, e.g. `["10.0.0.0/8", "::1/128"]`.
    /// Empty (default) means no peer is trusted and the client IP is always the TCP peer IP.
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_ip_networks")]
    pub cidrs: Vec<IpNet>,
    /// Trust **every** peer, regardless of `cidrs` (Traefik-style `insecure`).
    ///
    /// Dangerous: any client can then spoof `X-Forwarded-For` and the PROXY protocol header.
    /// Default `false`. Set to `true` to deliberately opt in (e.g. behind a controlled L4 LB);
    /// this also silences the over-broad `trusted_proxies` config warning.
    #[serde(default)]
    pub insecure: bool,
}

impl TrustedProxiesConfig {
    /// Whether the peer at `ip` is a trusted proxy (any peer when `insecure`).
    pub fn trusts(&self, ip: &IpAddr) -> bool {
        self.insecure || self.cidrs.iter().any(|net| net.contains(ip))
    }

    /// Whether at least one peer can be trusted (used to detect a `proxy_protocol` trust gap).
    pub fn has_trust(&self) -> bool {
        self.insecure || !self.cidrs.is_empty()
    }
}

pub(crate) fn default_max_connections() -> usize {
    512
}

/// Per-domain security policy override (`[domains.security]`).
///
/// Each field, when present, **fully replaces** the corresponding global policy for that
/// domain (whole-block replace, including the ability to disable a globally-enabled policy,
/// e.g. an `ip_filter` with `mode = "disabled"` or a `rate_limit` with `enabled = false`).
/// Fields left unset inherit the global `[security]` policy. `max_connections` is global only
/// (process-level, static) and is intentionally not part of this block.
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct DomainSecurityConfig {
    /// Security headers for this domain. Replaces global `[security.headers]` when present.
    #[serde(default)]
    pub headers: Option<SecurityHeaders>,
    /// IP filter (ACL) for this domain. Replaces global `[security.ip_filter]` when present.
    #[serde(default)]
    pub ip_filter: Option<IpFilterConfig>,
    /// Rate limit policy for this domain. Replaces global `[security.rate_limit]` when present.
    /// Per-route rate-limit overrides then overlay onto this domain-effective config.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Dynamic security configuration (hot-reloadable at runtime via ArcSwap)
///
/// Contains only the fields that can change without restart. `max_connections`
/// is excluded because it controls a process-level resource (ConnectionManager).
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityDynamicConfig {
    /// Security headers injected into responses
    pub headers: SecurityHeaders,
    /// IP allow/deny list
    pub ip_filter: IpFilterConfig,
    /// Rate limiting policy
    pub rate_limit: RateLimitConfig,
    /// Trusted reverse-proxy configuration (global, not overridable per scope).
    pub trusted_proxies: TrustedProxiesConfig,
}

/// Security headers configuration
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
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
/// Reference: RFC 6797 - <https://tools.ietf.org/html/rfc6797>
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
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
    /// Warning: Only enable if you plan to submit to <https://hstspreload.org/>
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
#[serde(deny_unknown_fields)]
pub struct CspConfig {
    /// Enable CSP
    #[serde(default)]
    pub enabled: bool,
    /// CSP policy string. Redacted on serialization: policies can reveal internal endpoints
    /// (e.g. `connect-src` hosts), so they are never exposed in the effective-config view or logs.
    #[serde(default = "default_csp_policy")]
    pub policy: Secret<String>,
}

impl Default for CspConfig {
    fn default() -> Self {
        Self { enabled: false, policy: default_csp_policy() }
    }
}

fn default_csp_policy() -> Secret<String> {
    Secret::new("default-src 'self'".to_string())
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Per-route security policy override (`[domains.routes.security]`).
///
/// Mirrors the per-domain `security` block (`global → domain → route`). Each field, when
/// present, **fully replaces** (whole-block) the domain-effective policy for that route; a
/// field left unset inherits the domain-effective (or global) policy.
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct RouteSecurityConfig {
    /// Security headers for this route. Replaces the domain/global `[security.headers]` when present.
    #[serde(default)]
    pub headers: Option<SecurityHeaders>,
    /// IP filter (ACL) for this route. Replaces the domain/global `[security.ip_filter]` when present.
    #[serde(default)]
    pub ip_filter: Option<IpFilterConfig>,
    /// Rate limit policy for this route. Replaces the domain/global `[security.rate_limit]` when present.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Rate limiting key extraction strategy
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LimitBy {
    /// Rate limit by client IP address.
    /// Uses the TCP peer (connection) IP by default. When `trusted_proxies` is configured,
    /// walks `X-Forwarded-For` right-to-left to find the first non-trusted IP.
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

/// Allowlisted effective-config view of the global [`SecurityDynamicConfig`].
#[derive(Serialize)]
pub(crate) struct SecurityView<'a> {
    headers: SecurityHeadersView<'a>,
    ip_filter: IpFilterView,
    rate_limit: RateLimitView<'a>,
    trusted_proxies: TrustedProxiesView,
}

#[derive(Serialize)]
struct TrustedProxiesView {
    cidrs: Vec<String>,
    insecure: bool,
}

/// Shared effective-config view for the per-domain and per-route `security` override blocks
/// ([`DomainSecurityConfig`] and [`RouteSecurityConfig`] have identical shapes).
#[derive(Serialize)]
pub(crate) struct ScopedSecurityView<'a> {
    headers: Option<SecurityHeadersView<'a>>,
    ip_filter: Option<IpFilterView>,
    rate_limit: Option<RateLimitView<'a>>,
}

#[derive(Serialize)]
struct SecurityHeadersView<'a> {
    custom: &'a [CustomHeader],
    hsts: HstsView,
    csp: CspView<'a>,
}

#[derive(Serialize)]
struct HstsView {
    enabled: bool,
    max_age: u64,
    include_subdomains: bool,
    preload: bool,
}

#[derive(Serialize)]
struct CspView<'a> {
    enabled: bool,
    policy: &'a Secret<String>,
}

#[derive(Serialize)]
struct IpFilterView {
    mode: &'static str,
    allowlist: Vec<String>,
    denylist: Vec<String>,
}

#[derive(Serialize)]
struct RateLimitView<'a> {
    enabled: bool,
    requests_per_second: u32,
    burst: u32,
    window_seconds: u64,
    limit_by: &'static str,
    limit_by_header: Option<&'a str>,
}

impl SecurityDynamicConfig {
    pub(crate) fn effective_view(&self) -> SecurityView<'_> {
        SecurityView {
            headers: self.headers.effective_view(),
            ip_filter: self.ip_filter.effective_view(),
            rate_limit: self.rate_limit.effective_view(),
            trusted_proxies: TrustedProxiesView {
                cidrs: self
                    .trusted_proxies
                    .cidrs
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                insecure: self.trusted_proxies.insecure,
            },
        }
    }
}

impl DomainSecurityConfig {
    pub(crate) fn effective_view(&self) -> ScopedSecurityView<'_> {
        ScopedSecurityView {
            headers: self.headers.as_ref().map(SecurityHeaders::effective_view),
            ip_filter: self.ip_filter.as_ref().map(IpFilterConfig::effective_view),
            rate_limit: self
                .rate_limit
                .as_ref()
                .map(RateLimitConfig::effective_view),
        }
    }
}

impl RouteSecurityConfig {
    pub(crate) fn effective_view(&self) -> ScopedSecurityView<'_> {
        ScopedSecurityView {
            headers: self.headers.as_ref().map(SecurityHeaders::effective_view),
            ip_filter: self.ip_filter.as_ref().map(IpFilterConfig::effective_view),
            rate_limit: self
                .rate_limit
                .as_ref()
                .map(RateLimitConfig::effective_view),
        }
    }
}

impl SecurityHeaders {
    fn effective_view(&self) -> SecurityHeadersView<'_> {
        SecurityHeadersView {
            custom: self.custom.as_slice(),
            hsts: HstsView {
                enabled: self.hsts.enabled,
                max_age: self.hsts.max_age,
                include_subdomains: self.hsts.include_subdomains,
                preload: self.hsts.preload,
            },
            csp: CspView { enabled: self.csp.enabled, policy: &self.csp.policy },
        }
    }
}

impl IpFilterConfig {
    fn effective_view(&self) -> IpFilterView {
        IpFilterView {
            mode: self.mode.as_str(),
            allowlist: self.allowlist.iter().map(ToString::to_string).collect(),
            denylist: self.denylist.iter().map(ToString::to_string).collect(),
        }
    }
}

impl RateLimitConfig {
    fn effective_view(&self) -> RateLimitView<'_> {
        RateLimitView {
            enabled: self.enabled,
            requests_per_second: self.requests_per_second,
            burst: self.burst,
            window_seconds: self.window_seconds,
            limit_by: self.limit_by.as_str(),
            limit_by_header: self.limit_by_header.as_deref(),
        }
    }
}

impl IpFilterMode {
    fn as_str(self) -> &'static str {
        match self {
            IpFilterMode::Disabled => "disabled",
            IpFilterMode::Allowlist => "allowlist",
            IpFilterMode::Denylist => "denylist",
        }
    }
}

impl LimitBy {
    fn as_str(self) -> &'static str {
        match self {
            LimitBy::Ip => "ip",
            LimitBy::Header => "header",
            LimitBy::Route => "route",
            LimitBy::Combined => "combined",
        }
    }
}
