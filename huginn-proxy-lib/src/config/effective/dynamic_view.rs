use serde_json::{json, Value};

use crate::config::dynamic::{
    Backend, BackendHttpVersion, Domain, DomainSecurityConfig, HeaderManipulation,
    HeaderManipulationGroup, HealthCheckType, IpFilterConfig, IpFilterMode, LimitBy,
    RateLimitConfig, Route, RouteSecurityConfig, SecurityHeaders,
};
use crate::config::DynamicConfig;

pub(super) fn dynamic_config_view(config: &DynamicConfig) -> Value {
    json!({
        "backends": config.backends.iter().map(backend_view).collect::<Vec<_>>(),
        "domains": config.domains.iter().map(domain_view).collect::<Vec<_>>(),
        "preserve_host": config.preserve_host,
        "headers": config.headers.as_ref().map(header_manipulation_view),
        "security": {
            "headers": security_headers_view(&config.security.headers),
            "ip_filter": ip_filter_view(&config.security.ip_filter),
            "rate_limit": rate_limit_view(&config.security.rate_limit),
            "trusted_proxies": config.security.trusted_proxies
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        },
        "backend_pool": {
            "enabled": config.backend_pool.enabled,
            "idle_timeout": config.backend_pool.idle_timeout,
            "pool_max_idle_per_host": config.backend_pool.pool_max_idle_per_host,
        },
    })
}

fn backend_view(backend: &Backend) -> Value {
    let health_check = backend.health_check.as_ref().map(|health| {
        let check_type = match &health.check_type {
            HealthCheckType::Tcp => json!({ "type": "tcp" }),
            HealthCheckType::Http { path, expected_status } => {
                json!({ "type": "http", "path": path, "expected_status": expected_status })
            }
        };
        json!({
            "check": check_type,
            "interval_secs": health.interval_secs,
            "timeout_secs": health.timeout_secs,
            "unhealthy_threshold": health.unhealthy_threshold,
            "healthy_threshold": health.healthy_threshold,
        })
    });

    json!({
        "address": backend.address,
        "http_version": backend.http_version.map(backend_http_version),
        "health_check": health_check,
    })
}

fn domain_view(domain: &Domain) -> Value {
    json!({
        "host": domain.host,
        "cert_configured": domain.cert_path.is_some(),
        "private_key_configured": domain.key_path.is_some(),
        "headers": domain.headers.as_ref().map(header_manipulation_view),
        "security": domain.security.as_ref().map(domain_security_view),
        "fingerprinting": domain.fingerprinting,
        "routes": domain.routes.iter().map(route_view).collect::<Vec<_>>(),
    })
}

fn route_view(route: &Route) -> Value {
    json!({
        "prefix": route.prefix,
        "backend": route.backend,
        "fingerprinting": route.fingerprinting,
        "force_new_connection": route.force_new_connection,
        "replace_path": route.replace_path,
        "security": route.security.as_ref().map(route_security_view),
        "headers": route.headers.as_ref().map(header_manipulation_view),
    })
}

fn domain_security_view(config: &DomainSecurityConfig) -> Value {
    json!({
        "headers": config.headers.as_ref().map(security_headers_view),
        "ip_filter": config.ip_filter.as_ref().map(ip_filter_view),
        "rate_limit": config.rate_limit.as_ref().map(rate_limit_view),
    })
}

fn route_security_view(config: &RouteSecurityConfig) -> Value {
    json!({
        "headers": config.headers.as_ref().map(security_headers_view),
        "ip_filter": config.ip_filter.as_ref().map(ip_filter_view),
        "rate_limit": config.rate_limit.as_ref().map(rate_limit_view),
    })
}

fn header_manipulation_view(config: &HeaderManipulation) -> Value {
    json!({
        "request": header_group_view(&config.request),
        "response": header_group_view(&config.response),
    })
}

fn header_group_view(config: &HeaderManipulationGroup) -> Value {
    json!({
        "add": config.add.iter().map(|header| {
            json!({ "name": header.name, "value": header.value })
        }).collect::<Vec<_>>(),
        "remove": config.remove,
    })
}

fn security_headers_view(config: &SecurityHeaders) -> Value {
    json!({
        "custom": config.custom.iter().map(|header| {
            json!({ "name": header.name, "value": header.value })
        }).collect::<Vec<_>>(),
        "hsts": {
            "enabled": config.hsts.enabled,
            "max_age": config.hsts.max_age,
            "include_subdomains": config.hsts.include_subdomains,
            "preload": config.hsts.preload,
        },
        "csp": {
            "enabled": config.csp.enabled,
            "policy": config.csp.policy,
        },
    })
}

fn ip_filter_view(config: &IpFilterConfig) -> Value {
    json!({
        "mode": ip_filter_mode(config.mode),
        "allowlist": config.allowlist.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "denylist": config.denylist.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

fn rate_limit_view(config: &RateLimitConfig) -> Value {
    json!({
        "enabled": config.enabled,
        "requests_per_second": config.requests_per_second,
        "burst": config.burst,
        "window_seconds": config.window_seconds,
        "limit_by": limit_by(config.limit_by),
        "limit_by_header": config.limit_by_header,
    })
}

fn backend_http_version(version: BackendHttpVersion) -> &'static str {
    match version {
        BackendHttpVersion::Http11 => "http11",
        BackendHttpVersion::Http2 => "http2",
        BackendHttpVersion::Preserve => "preserve",
    }
}

fn ip_filter_mode(mode: IpFilterMode) -> &'static str {
    match mode {
        IpFilterMode::Disabled => "disabled",
        IpFilterMode::Allowlist => "allowlist",
        IpFilterMode::Denylist => "denylist",
    }
}

fn limit_by(strategy: LimitBy) -> &'static str {
    match strategy {
        LimitBy::Ip => "ip",
        LimitBy::Header => "header",
        LimitBy::Route => "route",
        LimitBy::Combined => "combined",
    }
}
