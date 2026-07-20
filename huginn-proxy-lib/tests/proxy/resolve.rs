use huginn_proxy_lib::config::{
    Domain, DomainSecurityConfig, HstsConfig, IpFilterConfig, IpFilterMode, RateLimitConfig, Route,
    RouteSecurityConfig, SecurityHeaders, TrustedProxiesConfig,
};
use huginn_proxy_lib::proxy::handler::resolve::domain_defers_ip_filter;
use huginn_proxy_lib::proxy::handler::resolve_security;
use huginn_proxy_lib::proxy::router::pick_route_with_fingerprinting;
use huginn_proxy_lib::proxy::SecurityContext;

type R = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// IP filter distinguished purely by `mode` (no CIDR parsing needed): global=Denylist,
/// domain=Allowlist, route=Disabled. The effective mode reveals which scope won.
fn ip_filter(mode: IpFilterMode) -> IpFilterConfig {
    IpFilterConfig { mode, ..IpFilterConfig::default() }
}

fn headers(max_age: u64) -> SecurityHeaders {
    SecurityHeaders {
        hsts: HstsConfig { enabled: true, max_age, ..HstsConfig::default() },
        ..SecurityHeaders::default()
    }
}

fn ctx(ip_filter: IpFilterConfig, headers: SecurityHeaders) -> SecurityContext {
    SecurityContext::new(
        headers,
        ip_filter,
        RateLimitConfig::default(),
        None,
        None,
        TrustedProxiesConfig::default(),
    )
}

fn route(security: Option<RouteSecurityConfig>, fingerprinting: Option<bool>) -> Route {
    Route {
        prefix: "/".to_string(),
        backend: "backend:80".to_string(),
        fingerprinting,
        force_new_connection: false,
        replace_path: None,
        security,
        headers: None,
    }
}

fn domain(
    security: Option<DomainSecurityConfig>,
    fingerprinting: Option<bool>,
    routes: Vec<Route>,
) -> Domain {
    Domain {
        host: Some("a.com".to_string()),
        cert_path: None,
        key_path: None,
        headers: None,
        security,
        fingerprinting,
        routes,
    }
}

#[test]
fn ip_filter_resolves_route_over_domain_over_global() -> R {
    let global = ctx(ip_filter(IpFilterMode::Denylist), SecurityHeaders::default());

    // Route override wins over domain and global.
    let d = domain(
        Some(DomainSecurityConfig {
            ip_filter: Some(ip_filter(IpFilterMode::Allowlist)),
            ..DomainSecurityConfig::default()
        }),
        None,
        vec![route(
            Some(RouteSecurityConfig {
                ip_filter: Some(ip_filter(IpFilterMode::Disabled)),
                ..RouteSecurityConfig::default()
            }),
            None,
        )],
    );
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert_eq!(resolve_security(&global, Some(&d), &rm).ip_filter.mode, IpFilterMode::Disabled);

    // No route override → domain wins.
    let d = domain(
        Some(DomainSecurityConfig {
            ip_filter: Some(ip_filter(IpFilterMode::Allowlist)),
            ..DomainSecurityConfig::default()
        }),
        None,
        vec![route(None, None)],
    );
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert_eq!(resolve_security(&global, Some(&d), &rm).ip_filter.mode, IpFilterMode::Allowlist);

    // No domain or route override → global wins.
    let d = domain(None, None, vec![route(None, None)]);
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert_eq!(resolve_security(&global, Some(&d), &rm).ip_filter.mode, IpFilterMode::Denylist);
    Ok(())
}

#[test]
fn security_headers_resolve_route_over_domain_over_global() -> R {
    let global = ctx(IpFilterConfig::default(), headers(10));

    let d = domain(
        Some(DomainSecurityConfig {
            headers: Some(headers(20)),
            ..DomainSecurityConfig::default()
        }),
        None,
        vec![route(
            Some(RouteSecurityConfig {
                headers: Some(headers(30)),
                ..RouteSecurityConfig::default()
            }),
            None,
        )],
    );
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert_eq!(
        resolve_security(&global, Some(&d), &rm)
            .security_headers
            .hsts
            .max_age,
        30
    );

    let d = domain(
        Some(DomainSecurityConfig {
            headers: Some(headers(20)),
            ..DomainSecurityConfig::default()
        }),
        None,
        vec![route(None, None)],
    );
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert_eq!(
        resolve_security(&global, Some(&d), &rm)
            .security_headers
            .hsts
            .max_age,
        20
    );

    let d = domain(None, None, vec![route(None, None)]);
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert_eq!(
        resolve_security(&global, Some(&d), &rm)
            .security_headers
            .hsts
            .max_age,
        10
    );
    Ok(())
}

#[test]
fn fingerprinting_resolves_route_over_domain_over_default() -> R {
    let global = ctx(IpFilterConfig::default(), SecurityHeaders::default());

    // Route explicitly off beats domain on.
    let d = domain(None, Some(true), vec![route(None, Some(false))]);
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert!(!resolve_security(&global, Some(&d), &rm).fingerprinting);

    // Route unset → domain decides.
    let d = domain(None, Some(false), vec![route(None, None)]);
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert!(!resolve_security(&global, Some(&d), &rm).fingerprinting);

    // Neither set → default true.
    let d = domain(None, None, vec![route(None, None)]);
    let rm = pick_route_with_fingerprinting("/", &d.routes).ok_or("route should match")?;
    assert!(resolve_security(&global, Some(&d), &rm).fingerprinting);
    Ok(())
}

#[test]
fn domain_defers_ip_filter_only_with_route_override() {
    // No route override → check stays pre-routing.
    let d = domain(
        Some(DomainSecurityConfig {
            ip_filter: Some(ip_filter(IpFilterMode::Denylist)),
            ..DomainSecurityConfig::default()
        }),
        None,
        vec![route(None, None)],
    );
    assert!(!domain_defers_ip_filter(&d));

    // A route sets its own ip_filter → defer to post-routing.
    let d = domain(
        None,
        None,
        vec![route(
            Some(RouteSecurityConfig {
                ip_filter: Some(ip_filter(IpFilterMode::Allowlist)),
                ..RouteSecurityConfig::default()
            }),
            None,
        )],
    );
    assert!(domain_defers_ip_filter(&d));
}
