use serde_json::{json, Value};

use crate::config::startup::{ClientAuth, ProxyProtocolMode, StaticConfig, TlsConfig, TlsVersion};

pub(super) fn static_config_view(config: &StaticConfig) -> Value {
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

pub(super) fn proxy_protocol_mode(mode: ProxyProtocolMode) -> &'static str {
    match mode {
        ProxyProtocolMode::Off => "off",
        ProxyProtocolMode::Optional => "optional",
        ProxyProtocolMode::Require => "require",
    }
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

fn tls_version(version: TlsVersion) -> &'static str {
    match version {
        TlsVersion::V1_2 => "1.2",
        TlsVersion::V1_3 => "1.3",
    }
}
