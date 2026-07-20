use serde::Serialize;

use super::dynamic::DynamicView;
use super::startup::{StaticConfig, StaticView};
use super::DynamicConfig;

/// Serializable, secret-safe representation of the effective runtime configuration.
///
/// This type is intentionally built from an allowlist of fields instead of serializing
/// [`StaticConfig`] or [`DynamicConfig`] directly. The exposed surface is the set of fields
/// declared on the `*View` structs, each defined next to the config type it mirrors (e.g.
/// `ListenView` in `startup::listen`, `SecurityView` in `dynamic::security`), so adding a field to
/// the output is a deliberate, compiler-checked edit rather than a stringly-typed key.
/// Certificate/key paths and mTLS CA paths are reduced to booleans; header values and CSP policy
/// contents keep their [`Secret`](super::Secret) type and serialize as `<redacted>` by construction.
#[derive(Serialize)]
pub struct EffectiveConfigView<'a> {
    #[serde(rename = "static")]
    static_config: StaticView<'a>,
    #[serde(rename = "dynamic")]
    dynamic_config: DynamicView<'a>,
}

/// Safe aggregate values logged once when the proxy becomes ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EffectiveConfigSummary {
    pub listener_count: usize,
    pub tls_enabled: bool,
    pub proxy_protocol_mode: &'static str,
    pub domain_count: usize,
    pub route_count: usize,
    pub backend_count: usize,
    pub rate_limit_enabled: bool,
    pub trusted_proxy_count: usize,
    pub preserve_host: bool,
    pub max_connections: usize,
}

impl<'a> EffectiveConfigView<'a> {
    pub fn new(static_cfg: &'a StaticConfig, dynamic_cfg: &'a DynamicConfig) -> Self {
        Self {
            static_config: static_cfg.effective_view(),
            dynamic_config: dynamic_cfg.effective_view(),
        }
    }

    pub fn to_pretty_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

impl EffectiveConfigSummary {
    pub fn new(static_cfg: &StaticConfig, dynamic_cfg: &DynamicConfig) -> Self {
        let route_count = dynamic_cfg
            .domains
            .iter()
            .fold(0usize, |count, domain| count.saturating_add(domain.routes.len()));
        let rate_limit_enabled = dynamic_cfg.security.rate_limit.enabled
            || dynamic_cfg.domains.iter().any(|domain| {
                domain
                    .security
                    .as_ref()
                    .and_then(|security| security.rate_limit.as_ref())
                    .is_some_and(|rate_limit| rate_limit.enabled)
                    || domain.routes.iter().any(|route| {
                        route
                            .security
                            .as_ref()
                            .and_then(|security| security.rate_limit.as_ref())
                            .is_some_and(|rate_limit| rate_limit.enabled)
                    })
            });

        Self {
            listener_count: static_cfg.listen.addrs.len(),
            tls_enabled: static_cfg.tls.is_some(),
            proxy_protocol_mode: static_cfg.listen.proxy_protocol.mode.as_str(),
            domain_count: dynamic_cfg.domains.len(),
            route_count,
            backend_count: dynamic_cfg.backends.len(),
            rate_limit_enabled,
            trusted_proxy_count: dynamic_cfg.security.trusted_proxies.cidrs.len(),
            preserve_host: dynamic_cfg.preserve_host,
            max_connections: static_cfg.max_connections,
        }
    }
}
