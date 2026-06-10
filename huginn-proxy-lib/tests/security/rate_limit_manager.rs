use huginn_proxy_lib::config::{
    Domain, DomainSecurityConfig, RateLimitConfig, Route, RouteRateLimitConfig, RouteSecurityConfig,
};
use huginn_proxy_lib::security::RateLimitManager;

const DEFAULT_LABEL: &str = "_default_";

fn rl(enabled: bool, rps: u32, burst: u32) -> RateLimitConfig {
    RateLimitConfig { enabled, requests_per_second: rps, burst, ..RateLimitConfig::default() }
}

fn route(prefix: &str, rate_limit: Option<RouteRateLimitConfig>) -> Route {
    Route {
        prefix: prefix.to_string(),
        backend: "backend:80".to_string(),
        fingerprinting: false,
        force_new_connection: false,
        replace_path: None,
        security: rate_limit.map(|rl| RouteSecurityConfig { rate_limit: Some(rl) }),
        headers: None,
    }
}

fn domain(
    host: Option<&str>,
    security: Option<DomainSecurityConfig>,
    routes: Vec<Route>,
) -> Domain {
    Domain {
        host: host.map(str::to_string),
        cert_path: None,
        key_path: None,
        headers: None,
        security,
        routes,
    }
}

fn sec(rate_limit: RateLimitConfig) -> DomainSecurityConfig {
    DomainSecurityConfig { rate_limit: Some(rate_limit), ..DomainSecurityConfig::default() }
}

/// A domain `rate_limit` override replaces the global policy for that domain, while a domain
/// without an override still uses the global limiter.
#[test]
fn domain_override_replaces_global() {
    let global = rl(true, 100, 100);
    let domains = vec![
        // a.com: tighter override (burst 1).
        domain(Some("a.com"), Some(sec(rl(true, 1, 1))), vec![]),
        // b.com: no override → inherits global (burst 100).
        domain(Some("b.com"), None, vec![]),
    ];
    let mgr = RateLimitManager::new(&global, &domains);

    // a.com is exhausted after a single request (burst 1).
    assert!(mgr.check("ip", "a.com", None).is_allowed());
    assert!(mgr.check("ip", "a.com", None).is_limited());

    // b.com still has the generous global burst.
    for _ in 0..100 {
        assert!(mgr.check("ip", "b.com", None).is_allowed());
    }
}

/// A domain that explicitly disables rate limiting (`enabled = false`) must NOT fall through to
/// an enabled global limiter.
#[test]
fn domain_explicit_disable_does_not_fall_through_to_global() {
    let global = rl(true, 1, 1);
    let domains = vec![
        domain(Some("free.com"), Some(sec(rl(false, 1, 1))), vec![]),
        domain(Some("paid.com"), None, vec![]),
    ];
    let mgr = RateLimitManager::new(&global, &domains);

    // free.com disabled rate limiting: every request is allowed.
    for _ in 0..50 {
        assert!(mgr.check("ip", "free.com", None).is_allowed());
    }

    // paid.com inherits the global burst of 1.
    assert!(mgr.check("ip", "paid.com", None).is_allowed());
    assert!(mgr.check("ip", "paid.com", None).is_limited());
}

/// A per-route override beats the domain-effective config; the route limiter wins.
#[test]
fn route_override_beats_domain() {
    let global = rl(false, 1000, 1000);
    let route_rl = RouteRateLimitConfig {
        enabled: Some(true),
        requests_per_second: Some(1),
        burst: Some(1),
        window_seconds: None,
        limit_by: None,
        limit_by_header: None,
    };
    let domains = vec![domain(
        Some("a.com"),
        Some(sec(rl(true, 100, 100))),
        vec![route("/tight", Some(route_rl))],
    )];
    let mgr = RateLimitManager::new(&global, &domains);

    // The route limiter (burst 1) applies on /tight.
    assert!(mgr.check("ip", "a.com", Some("/tight")).is_allowed());
    assert!(mgr.check("ip", "a.com", Some("/tight")).is_limited());

    // A different (unmatched) prefix on the same domain falls back to the domain limiter (burst 100).
    for _ in 0..100 {
        assert!(mgr.check("ip", "a.com", Some("/other")).is_allowed());
    }
}

/// The same route prefix under two domains uses independent limiters (no cross-domain collision).
#[test]
fn same_prefix_isolated_across_domains() {
    let global = rl(false, 1000, 1000);
    let mk_route = || {
        route(
            "/",
            Some(RouteRateLimitConfig {
                enabled: Some(true),
                requests_per_second: Some(1),
                burst: Some(1),
                window_seconds: None,
                limit_by: None,
                limit_by_header: None,
            }),
        )
    };
    let domains = vec![
        domain(Some("a.com"), None, vec![mk_route()]),
        domain(Some("b.com"), None, vec![mk_route()]),
    ];
    let mgr = RateLimitManager::new(&global, &domains);

    // Exhaust a.com's "/" limiter.
    assert!(mgr.check("ip", "a.com", Some("/")).is_allowed());
    assert!(mgr.check("ip", "a.com", Some("/")).is_limited());

    // b.com's "/" limiter is independent and still fresh.
    assert!(mgr.check("ip", "b.com", Some("/")).is_allowed());
    assert!(mgr.check("ip", "b.com", Some("/")).is_limited());
}

/// The catch-all (host-less) domain is addressed by the `_default_` label.
#[test]
fn catch_all_domain_uses_default_label() {
    let global = rl(false, 1000, 1000);
    let domains = vec![domain(None, Some(sec(rl(true, 1, 1))), vec![])];
    let mgr = RateLimitManager::new(&global, &domains);

    assert!(mgr.check("ip", DEFAULT_LABEL, None).is_allowed());
    assert!(mgr.check("ip", DEFAULT_LABEL, None).is_limited());
}

/// `is_enabled` reflects global, per-domain, and per-route limiters.
#[test]
fn is_enabled_tracks_all_limiter_sources() {
    // Nothing enabled anywhere.
    let mgr = RateLimitManager::new(&rl(false, 1, 1), &[domain(Some("a.com"), None, vec![])]);
    assert!(!mgr.is_enabled());

    // Enabled solely via a per-domain override.
    let mgr = RateLimitManager::new(
        &rl(false, 1, 1),
        &[domain(Some("a.com"), Some(sec(rl(true, 1, 1))), vec![])],
    );
    assert!(mgr.is_enabled());

    // A domain that only *disables* rate limiting does not count as enabled.
    let mgr = RateLimitManager::new(
        &rl(false, 1, 1),
        &[domain(Some("a.com"), Some(sec(rl(false, 1, 1))), vec![])],
    );
    assert!(!mgr.is_enabled());
}
