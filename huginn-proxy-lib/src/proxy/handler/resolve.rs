use crate::config::{Domain, IpFilterConfig, SecurityHeaders, DEFAULT_FINGERPRINTING};
use crate::proxy::router::RouteMatch;
use crate::proxy::SecurityContext;

/// Effective per-request security policy after whole-block resolution.
///
/// Every field is resolved `route.or(domain).or(global)`: the most specific scope that sets a
/// block wins **entirely** (no field-level merge). `fingerprinting` falls back to
/// [`DEFAULT_FINGERPRINTING`] when neither route nor domain sets it.
pub struct EffectiveSecurity<'a> {
    pub ip_filter: &'a IpFilterConfig,
    pub security_headers: &'a SecurityHeaders,
    pub fingerprinting: bool,
}

/// Resolve the effective `ip_filter`, `security_headers`, and `fingerprinting` gate for a matched
/// route. Rate limiting is intentionally excluded: its limiters are stateful and precomputed in
/// [`crate::security::RateLimitManager`], keyed by domain label + route prefix.
pub fn resolve_security<'a>(
    global: &'a SecurityContext,
    domain: Option<&'a Domain>,
    route: &RouteMatch<'a>,
) -> EffectiveSecurity<'a> {
    let domain_sec = domain.and_then(|d| d.security.as_ref());

    let ip_filter = route
        .ip_filter
        .or_else(|| domain_sec.and_then(|s| s.ip_filter.as_ref()))
        .unwrap_or(&global.ip_filter);

    let security_headers = route
        .security_headers
        .or_else(|| domain_sec.and_then(|s| s.headers.as_ref()))
        .unwrap_or(&global.headers);

    let fingerprinting = route
        .fingerprinting
        .or_else(|| domain.and_then(|d| d.fingerprinting))
        .unwrap_or(DEFAULT_FINGERPRINTING);

    EffectiveSecurity { ip_filter, security_headers, fingerprinting }
}

/// Whether any route in `domain` defines its own `ip_filter` override.
///
/// `true` defers the IP check to after route match (route-dependent filter, Traefik's router-level
/// ACL); `false` lets it run before routing, where the domain/global filter applies uniformly.
pub fn domain_defers_ip_filter(domain: &Domain) -> bool {
    domain.routes.iter().any(|r| {
        r.security
            .as_ref()
            .and_then(|s| s.ip_filter.as_ref())
            .is_some()
    })
}
