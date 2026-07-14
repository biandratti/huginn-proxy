use serde::Serialize;
use serde_json::{json, Value};

use super::dynamic::{
    Backend, BackendHttpVersion, Domain, DomainSecurityConfig, HeaderManipulation,
    HeaderManipulationGroup, HealthCheckType, IpFilterConfig, IpFilterMode, LimitBy,
    RateLimitConfig, Route, RouteSecurityConfig, SecurityHeaders,
};
use super::startup::{ClientAuth, ProxyProtocolMode, StaticConfig, TlsConfig, TlsVersion};
use super::DynamicConfig;

const REDACTED: &str = "<redacted>";

/// Serializable, secret-safe representation of the effective runtime configuration.
///
/// This type is intentionally built from an allowlist of fields instead of serializing
/// [`StaticConfig`] or [`DynamicConfig`] directly. Header values, certificate/key paths, mTLS CA
/// paths, and CSP policy contents are never copied into this view.
#[derive(Debug, Serialize)]
pub struct EffectiveConfigView {
    #[serde(rename = "static")]
    static_config: Value,
    #[serde(rename = "dynamic")]
    dynamic_config: Value,
}

impl EffectiveConfigView {
    /// Build a redacted view from the configuration actually used by the runtime.
    pub fn new(static_cfg: &StaticConfig, dynamic_cfg: &DynamicConfig) -> Self {
        Self {
            static_config: static_config_view(static_cfg),
            dynamic_config: dynamic_config_view(dynamic_cfg),
        }
    }

    /// Serialize the view as deterministic, pretty-printed JSON.
    pub fn to_pretty_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

fn static_config_view(config: &StaticConfig) -> Value {
    json!({
        "listen": {
            "addrs": config.listen.addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "tcp_backlog": config.listen.tcp_backlog,
            "proxy_protocol": {
                "mode": proxy_protocol_mode(config.listen.proxy_protocol.mode),
                "header_timeout_ms": config.listen.proxy_protocol.header_timeout_ms,
            },
        },
        "tls": tls_view(config.tls.as_ref()),
        "fingerprint": {
            "tls_enabled": config.fingerprint.tls_enabled,
            "http_enabled": config.fingerprint.http_enabled,
            "tcp_enabled": config.fingerprint.tcp_enabled,
            "max_capture": config.fingerprint.max_capture,
        },
        "logging": {
            "level": config.logging.level,
            "show_target": config.logging.show_target,
        },
        "timeout": {
            "upstream_connect_ms": config.timeout.upstream_connect_ms,
            "proxy_idle_ms": config.timeout.proxy_idle_ms,
            "shutdown_secs": config.timeout.shutdown_secs,
            "tls_handshake_secs": config.timeout.tls_handshake_secs,
            "connection_handling_secs": config.timeout.connection_handling_secs,
            "keep_alive": {
                "enabled": config.timeout.keep_alive.enabled,
                "upstream_idle_timeout": config.timeout.keep_alive.upstream_idle_timeout,
            },
        },
        "telemetry": {
            "metrics_port": config.telemetry.metrics_port,
            "otel_log_level": config.telemetry.otel_log_level,
        },
        "max_connections": config.max_connections,
    })
}

fn dynamic_config_view(config: &DynamicConfig) -> Value {
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

fn tls_view(config: Option<&TlsConfig>) -> Value {
    let Some(config) = config else {
        return json!({ "enabled": false });
    };

    let client_auth = match &config.client_auth {
        ClientAuth::Disabled => json!({ "mode": "disabled" }),
        ClientAuth::Required { .. } => {
            json!({ "mode": "required", "ca_certificate_configured": true })
        }
    };

    json!({
        "enabled": true,
        "alpn": config.alpn,
        "options": {
            "versions": config.options.versions.iter().map(|version| tls_version(*version)).collect::<Vec<_>>(),
            "min_version": config.options.min_version.map(tls_version),
            "max_version": config.options.max_version.map(tls_version),
            "cipher_suites": config.options.cipher_suites,
            "curve_preferences": config.options.curve_preferences,
            "sni_strict": config.options.sni_strict,
        },
        "client_auth": client_auth,
        "session_resumption": {
            "enabled": config.session_resumption.enabled,
            "max_sessions": config.session_resumption.max_sessions,
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
            json!({ "name": header.name, "value": REDACTED })
        }).collect::<Vec<_>>(),
        "remove": config.remove,
    })
}

fn security_headers_view(config: &SecurityHeaders) -> Value {
    json!({
        "custom": config.custom.iter().map(|header| {
            json!({ "name": header.name, "value": REDACTED })
        }).collect::<Vec<_>>(),
        "hsts": {
            "enabled": config.hsts.enabled,
            "max_age": config.hsts.max_age,
            "include_subdomains": config.hsts.include_subdomains,
            "preload": config.hsts.preload,
        },
        "csp": {
            "enabled": config.csp.enabled,
            "policy": REDACTED,
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

fn proxy_protocol_mode(mode: ProxyProtocolMode) -> &'static str {
    match mode {
        ProxyProtocolMode::Off => "off",
        ProxyProtocolMode::Optional => "optional",
        ProxyProtocolMode::Require => "require",
    }
}

fn tls_version(version: TlsVersion) -> &'static str {
    match version {
        TlsVersion::V1_2 => "1.2",
        TlsVersion::V1_3 => "1.3",
    }
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
