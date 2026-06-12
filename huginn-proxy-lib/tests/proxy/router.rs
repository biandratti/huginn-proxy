use huginn_proxy_lib::config::{sort_domain_routes, sort_routes, Domain, Route};
use huginn_proxy_lib::proxy::router::{
    authority_matches_sni, pick_domain, pick_route, pick_route_with_fingerprinting, prefix_matches,
};

fn route(prefix: &str, backend: &str) -> Route {
    Route {
        prefix: prefix.to_string(),
        backend: backend.to_string(),
        fingerprinting: Some(true),
        force_new_connection: false,
        replace_path: None,
        security: None,
        headers: None,
    }
}

fn sorted_routes(mut routes: Vec<Route>) -> Vec<Route> {
    sort_routes(&mut routes);
    routes
}

fn domain(host: &str, routes: Vec<Route>) -> Domain {
    Domain {
        host: Some(host.to_string()),
        cert_path: None,
        key_path: None,
        headers: None,
        security: None,
        fingerprinting: None,
        routes,
    }
}

fn domain_with_cert(host: &str, cert_path: &str) -> Domain {
    Domain {
        host: Some(host.to_string()),
        cert_path: Some(cert_path.to_string()),
        key_path: Some(format!("{cert_path}.key")),
        headers: None,
        security: None,
        fingerprinting: None,
        routes: vec![],
    }
}

/// A host-less (catch-all) domain matches any host not matched exactly/by wildcard.
fn catch_all(routes: Vec<Route>) -> Domain {
    Domain {
        host: None,
        cert_path: None,
        key_path: None,
        headers: None,
        security: None,
        fingerprinting: None,
        routes,
    }
}

fn sorted_domains(mut domains: Vec<Domain>) -> Vec<Domain> {
    sort_domain_routes(&mut domains);
    domains
}

#[test]
fn test_pick_route() {
    let routes = vec![
        route("/api", "backend-a:9000"),
        route("/static", "backend-b:9000"),
        route("/", "backend-c:9000"),
    ];

    assert_eq!(pick_route("/api/users", &routes), Some("backend-a:9000"));
    assert_eq!(pick_route("/static/css", &routes), Some("backend-b:9000"));
    assert_eq!(pick_route("/other", &routes), Some("backend-c:9000"));
    assert_eq!(pick_route("/", &routes), Some("backend-c:9000"));
    assert_eq!(pick_route("/unknown", &routes), Some("backend-c:9000"));
}

#[test]
fn test_pick_route_empty() {
    let routes: Vec<Route> = vec![];
    assert_eq!(pick_route("/api", &routes), None);
}

#[test]
fn test_pick_route_with_fingerprinting_basic() {
    let routes = vec![route("/api", "backend-a:9000")];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(r) = result {
        assert_eq!(r.backend, "backend-a:9000");
        assert_eq!(r.backend_candidates, vec!["backend-a:9000"]);
        assert_eq!(r.fingerprinting, Some(true));
        assert_eq!(r.matched_prefix, "/api");
        assert!(r.replace_path.is_none());
    }
}

#[test]
fn test_pick_route_with_fingerprinting_with_replace_path() {
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend-a:9000".to_string(),
        fingerprinting: Some(true),
        replace_path: Some("/v1".to_string()),
        security: None,
        headers: None,
        force_new_connection: false,
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(r) = result {
        assert_eq!(r.backend, "backend-a:9000");
        assert_eq!(r.matched_prefix, "/api");
        assert_eq!(r.replace_path, Some("/v1"));
    }
}

#[test]
fn test_pick_route_with_fingerprinting_path_stripping() {
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend-a:9000".to_string(),
        fingerprinting: Some(false),
        replace_path: Some("".to_string()),
        security: None,
        headers: None,
        force_new_connection: false,
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(r) = result {
        assert_eq!(r.fingerprinting, Some(false));
        assert_eq!(r.replace_path, Some(""));
    }
}

#[test]
fn test_pick_route_with_fingerprinting_collects_same_prefix_candidates() {
    let routes = vec![
        route("/api", "backend-a:9000"),
        route("/api", "backend-b:9000"),
        route("/", "backend-c:9000"),
    ];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(r) = result {
        assert_eq!(r.matched_prefix, "/api");
        assert_eq!(r.backend, "backend-a:9000");
        assert_eq!(r.backend_candidates, vec!["backend-a:9000", "backend-b:9000"]);
    }
}

#[test]
fn longest_prefix_wins_over_declaration_order() {
    let routes = sorted_routes(vec![
        route("/api", "backend-a:9000"),
        route("/api/e2e-unhealthy", "unreachable:9000"),
    ]);
    assert_eq!(pick_route("/api/e2e-unhealthy", &routes), Some("unreachable:9000"));
}

#[test]
fn longer_prefix_wins_regardless_of_order() {
    let routes = sorted_routes(vec![
        route("/api/e2e-unhealthy", "unreachable:9000"),
        route("/api", "backend-a:9000"),
    ]);
    assert_eq!(pick_route("/api/e2e-unhealthy", &routes), Some("unreachable:9000"));
}

#[test]
fn catch_all_root_matches_when_nothing_else_does() {
    let routes = sorted_routes(vec![route("/api", "backend-a:9000"), route("/", "catch-all:9000")]);
    assert_eq!(pick_route("/unknown/path", &routes), Some("catch-all:9000"));
}

#[test]
fn exact_match_preferred_over_root() {
    let routes = sorted_routes(vec![route("/", "catch-all:9000"), route("/api", "backend-a:9000")]);
    assert_eq!(pick_route("/api/users", &routes), Some("backend-a:9000"));
}

#[test]
fn no_match_without_catch_all_returns_none() {
    let routes = vec![route("/api", "backend-a:9000")];
    assert_eq!(pick_route("/static/file.js", &routes), None);
}

#[test]
fn false_positive_guard_api_vs_api2() {
    let routes =
        sorted_routes(vec![route("/api", "backend-a:9000"), route("/api2", "backend-b:9000")]);
    assert_eq!(pick_route("/api2/resource", &routes), Some("backend-b:9000"));
    assert_eq!(pick_route("/api/resource", &routes), Some("backend-a:9000"));
}

#[test]
fn three_level_nesting_picks_deepest() {
    let routes = sorted_routes(vec![
        route("/", "root:9000"),
        route("/api", "api:9000"),
        route("/api/v1", "apiv1:9000"),
    ]);
    assert_eq!(pick_route("/api/v1/users", &routes), Some("apiv1:9000"));
    assert_eq!(pick_route("/api/v2/users", &routes), Some("api:9000"));
    assert_eq!(pick_route("/other", &routes), Some("root:9000"));
}

#[test]
fn root_matches_any_path() {
    assert!(prefix_matches("/api/users", "/"));
    assert!(prefix_matches("/", "/"));
    assert!(prefix_matches("/anything", "/"));
}

#[test]
fn exact_match() {
    assert!(prefix_matches("/api", "/api"));
    assert!(prefix_matches("/static", "/static"));
}

#[test]
fn sub_path_match() {
    assert!(prefix_matches("/api/users", "/api"));
    assert!(prefix_matches("/api/v1/resource", "/api"));
}

#[test]
fn no_match_different_prefix() {
    assert!(!prefix_matches("/static/file.js", "/api"));
}

#[test]
fn no_false_positive_shared_prefix_no_slash_boundary() {
    assert!(!prefix_matches("/api2", "/api"));
    assert!(!prefix_matches("/api2/sub", "/api"));
    assert!(!prefix_matches("/apiv2", "/api"));
}

#[test]
fn longer_segment_does_not_match_shorter_prefix_without_slash() {
    assert!(!prefix_matches("/static2", "/static"));
    assert!(!prefix_matches("/staticfiles", "/static"));
}

#[test]
fn empty_path_does_not_match_non_root() {
    assert!(!prefix_matches("", "/api"));
}

#[test]
fn root_prefix_does_not_match_empty_path() {
    assert!(!prefix_matches("", "/"));
}

#[test]
fn fingerprinting_no_match_returns_none() {
    let routes = vec![route("/api", "backend-a:9000")];
    assert!(pick_route_with_fingerprinting("/static/file.js", &routes).is_none());
}

#[test]
fn fingerprinting_root_catch_all_candidates() {
    let routes = sorted_routes(vec![
        route("/api", "api:9000"),
        route("/", "root-a:9000"),
        route("/", "root-b:9000"),
    ]);
    let Some(r) = pick_route_with_fingerprinting("/unknown", &routes) else {
        panic!("Expected a route match for /unknown");
    };
    assert_eq!(r.matched_prefix, "/");
    assert_eq!(r.backend_candidates, vec!["root-a:9000", "root-b:9000"]);
}

#[test]
fn fingerprinting_candidates_stops_at_shorter_prefix() {
    let routes = sorted_routes(vec![
        route("/api", "api-a:9000"),
        route("/api", "api-b:9000"),
        route("/", "root:9000"),
    ]);
    let Some(r) = pick_route_with_fingerprinting("/api/users", &routes) else {
        panic!("Expected a route match for /api/users");
    };
    assert_eq!(r.backend_candidates, vec!["api-a:9000", "api-b:9000"]);
}

#[test]
fn fingerprinting_same_depth_different_prefix_not_included_in_candidates() {
    let routes = sorted_routes(vec![
        route("/api", "api-a:9000"),
        route("/web", "web:9000"),
        route("/api", "api-b:9000"),
    ]);
    let Some(r) = pick_route_with_fingerprinting("/api/users", &routes) else {
        panic!("Expected a route match for /api/users");
    };
    assert_eq!(r.matched_prefix, "/api");
    assert_eq!(r.backend_candidates, vec!["api-a:9000", "api-b:9000"]);
}

#[test]
fn exact_domain_match() {
    let domains = vec![domain("api.example.com", vec![]), domain("web.example.com", vec![])];
    let Some(d) = pick_domain(&domains, "api.example.com") else {
        panic!("expected exact match for api.example.com");
    };
    assert_eq!(d.host.as_deref(), Some("api.example.com"));
}

#[test]
fn wildcard_domain_matches_subdomain() {
    let domains = vec![domain("*.example.com", vec![])];
    let Some(d) = pick_domain(&domains, "sub.example.com") else {
        panic!("expected wildcard match for sub.example.com");
    };
    assert_eq!(d.host.as_deref(), Some("*.example.com"));
}

#[test]
fn wildcard_does_not_match_multilevel_subdomain() {
    // *.example.com must NOT match a.b.example.com (only one level)
    let domains = vec![domain("*.example.com", vec![])];
    assert!(pick_domain(&domains, "a.b.example.com").is_none());
}

#[test]
fn wildcard_does_not_match_base_domain() {
    // *.example.com must NOT match example.com itself
    let domains = vec![domain("*.example.com", vec![])];
    assert!(pick_domain(&domains, "example.com").is_none());
}

#[test]
fn exact_match_takes_priority_over_wildcard() {
    let domains = vec![
        domain("*.example.com", vec![route("/wildcard", "wc:9000")]),
        domain("api.example.com", vec![route("/exact", "exact:9000")]),
    ];
    let Some(d) = pick_domain(&domains, "api.example.com") else {
        panic!("expected exact match for api.example.com");
    };
    assert_eq!(d.host.as_deref(), Some("api.example.com"));
}

#[test]
fn no_match_returns_none() {
    let domains = vec![domain("api.example.com", vec![]), domain("web.example.com", vec![])];
    assert!(pick_domain(&domains, "other.example.com").is_none());
}

#[test]
fn empty_domains_returns_none() {
    let domains: Vec<Domain> = vec![];
    assert!(pick_domain(&domains, "api.example.com").is_none());
}

#[test]
fn ipv4_exact_match() {
    let domains = vec![domain("127.0.0.1", vec![])];
    assert!(pick_domain(&domains, "127.0.0.1").is_some());
}

#[test]
fn ipv6_exact_match() {
    let domains = vec![domain("::1", vec![])];
    assert!(pick_domain(&domains, "::1").is_some());
}

#[test]
fn domain_routes_are_accessible_after_pick() {
    let domains = sorted_domains(vec![domain(
        "api.example.com",
        vec![route("/api", "backend-a:9000"), route("/", "backend-b:9000")],
    )]);
    let Some(d) = pick_domain(&domains, "api.example.com") else {
        panic!("expected domain api.example.com");
    };
    assert_eq!(pick_route("/api/users", &d.routes), Some("backend-a:9000"));
}

#[test]
fn wildcard_and_two_phase_routing() {
    let domains = sorted_domains(vec![domain(
        "*.example.com",
        vec![route("/api", "api:9000"), route("/", "web:9000")],
    )]);
    let Some(d) = pick_domain(&domains, "tenant.example.com") else {
        panic!("expected wildcard match for tenant.example.com");
    };
    assert_eq!(pick_route("/api/data", &d.routes), Some("api:9000"));
    assert_eq!(pick_route("/home", &d.routes), Some("web:9000"));
}

#[test]
fn catch_all_matches_unknown_host() {
    let domains = vec![domain("api.example.com", vec![]), catch_all(vec![])];
    let Some(d) = pick_domain(&domains, "anything.else.com") else {
        panic!("expected catch-all to match unknown host");
    };
    assert!(d.host.is_none());
}

#[test]
fn catch_all_matches_ip_literals_and_localhost() {
    // The whole point: one host-less domain serves IPv4, IPv6 and localhost
    // without enumerating each as its own domain.
    let domains = vec![catch_all(vec![])];
    assert!(pick_domain(&domains, "127.0.0.1").is_some());
    assert!(pick_domain(&domains, "::1").is_some());
    assert!(pick_domain(&domains, "localhost").is_some());
}

#[test]
fn exact_and_wildcard_win_over_catch_all() {
    let domains = vec![
        domain("api.example.com", vec![]),
        domain("*.example.com", vec![]),
        catch_all(vec![]),
    ];
    // exact beats catch-all
    assert_eq!(
        pick_domain(&domains, "api.example.com").and_then(|d| d.host.as_deref()),
        Some("api.example.com")
    );
    // wildcard beats catch-all
    assert_eq!(
        pick_domain(&domains, "sub.example.com").and_then(|d| d.host.as_deref()),
        Some("*.example.com")
    );
    // everything else falls through to catch-all
    assert!(pick_domain(&domains, "other.org").is_some_and(|d| d.host.is_none()));
}

#[test]
fn no_catch_all_still_returns_none_for_unknown() {
    let domains = vec![domain("api.example.com", vec![])];
    assert!(pick_domain(&domains, "127.0.0.1").is_none());
    assert!(pick_domain(&domains, "unknown.com").is_none());
}

#[test]
fn authority_matches_sni_same_host() {
    let domains = vec![domain("api.example.com", vec![])];
    assert!(authority_matches_sni(&domains, "api.example.com", "api.example.com"));
}

#[test]
fn authority_matches_sni_is_case_insensitive_on_sni() {
    let domains = vec![domain("api.example.com", vec![])];
    // `host` arrives already lowercased; the SNI is lowercased internally.
    assert!(authority_matches_sni(&domains, "API.Example.COM", "api.example.com"));
}

#[test]
fn authority_matches_sni_allows_wildcard_coalescing() {
    // The coalescing case we must NOT break: two hosts served by one *.example.com cert.
    let domains = vec![domain("*.example.com", vec![])];
    assert!(authority_matches_sni(&domains, "api.example.com", "docs.example.com"));
}

#[test]
fn authority_matches_sni_rejects_cross_certificate() {
    // SNI selected the exact api cert; a request for a host on a *different* cert is rejected.
    let domains = vec![domain("api.example.com", vec![]), domain("*.example.com", vec![])];
    // SNI -> exact api.example.com; authority -> *.example.com (different domain/cert).
    assert!(!authority_matches_sni(&domains, "api.example.com", "docs.example.com"));
}

#[test]
fn authority_matches_sni_rejects_unrelated_host() {
    let domains = vec![domain("api.example.com", vec![])];
    // authority resolves to no domain at all -> not authoritative.
    assert!(!authority_matches_sni(&domains, "api.example.com", "evil.com"));
}

#[test]
fn authority_matches_sni_both_catch_all_match() {
    let domains = vec![catch_all(vec![])];
    assert!(authority_matches_sni(&domains, "anything.com", "other.com"));
}

#[test]
fn authority_matches_sni_specific_sni_vs_catch_all_host() {
    let domains = vec![domain("api.example.com", vec![]), catch_all(vec![])];
    // SNI -> exact domain, authority -> catch-all: different cert, reject.
    assert!(!authority_matches_sni(&domains, "api.example.com", "other.com"));
}

#[test]
fn authority_matches_sni_same_cert_file_coalesces() {
    // Two distinct domain entries pointing at the same SAN certificate file: the
    // connection's cert covers both, so coalescing must be allowed (no false 421).
    let domains = vec![
        domain_with_cert("api.example.com", "/certs/san.pem"),
        domain_with_cert("docs.example.com", "/certs/san.pem"),
    ];
    assert!(authority_matches_sni(&domains, "api.example.com", "docs.example.com"));
}

#[test]
fn authority_matches_sni_different_cert_files_rejected() {
    let domains = vec![
        domain_with_cert("api.example.com", "/certs/api.pem"),
        domain_with_cert("other.com", "/certs/other.pem"),
    ];
    // SNI selected api's cert; a request for other.com (a different cert) is misdirected.
    assert!(!authority_matches_sni(&domains, "api.example.com", "other.com"));
}

#[test]
fn authority_matches_sni_certless_host_uses_default_cert() {
    // A certless named domain is served by the default (catch-all) cert. A request for it
    // over a connection that also presented the default cert coalesces.
    let catch_all_with_cert = Domain {
        host: None,
        cert_path: Some("/certs/default.pem".to_string()),
        key_path: Some("/certs/default.key".to_string()),
        headers: None,
        security: None,
        fingerprinting: None,
        routes: vec![],
    };
    let domains = vec![domain("api.example.com", vec![]), catch_all_with_cert];
    // SNI=api.example.com -> certless -> default cert; authority=other -> catch-all -> default cert.
    assert!(authority_matches_sni(&domains, "api.example.com", "other.com"));
}
