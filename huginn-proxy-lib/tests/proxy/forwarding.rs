use http::Version;
use huginn_proxy_lib::config::{sort_routes, Backend, BackendHttpVersion, Route};
use huginn_proxy_lib::proxy::forwarding::{
    determine_http_version, find_backend_config, pick_route, prefix_matches,
};

fn route(prefix: &str, backend: &str) -> Route {
    Route {
        prefix: prefix.to_string(),
        backend: backend.to_string(),
        fingerprinting: true,
        force_new_connection: false,
        replace_path: None,
        rate_limit: None,
        headers: None,
    }
}

/// Mirrors what `Config::into_parts` does at startup.
/// Tests that exercise overlapping prefixes must call this, otherwise `pick_route`
/// (which uses `find` on a sorted slice) may return the wrong route.
fn sorted_routes(mut routes: Vec<Route>) -> Vec<Route> {
    sort_routes(&mut routes);
    routes
}

#[test]
fn test_find_backend_config() {
    let backends = vec![
        Backend {
            address: "backend-a:9000".to_string(),
            http_version: Some(BackendHttpVersion::Http2),
            health_check: None,
        },
        Backend {
            address: "backend-b:9000".to_string(),
            http_version: Some(BackendHttpVersion::Http11),
            health_check: None,
        },
    ];

    assert_eq!(
        find_backend_config("backend-a:9000", &backends).map(|b| b.address.as_str()),
        Some("backend-a:9000")
    );
    assert_eq!(
        find_backend_config("backend-b:9000", &backends).map(|b| b.address.as_str()),
        Some("backend-b:9000")
    );
    assert!(find_backend_config("backend-c:9000", &backends).is_none());
}

#[test]
fn test_determine_http_version_with_config() {
    let backend_http2 = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Http2),
        health_check: None,
    };
    let backend_http11 = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Http11),
        health_check: None,
    };
    let backend_preserve = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Preserve),
        health_check: None,
    };

    // Test with explicit http2 config
    assert_eq!(
        determine_http_version(Some(&backend_http2), Version::HTTP_11, false),
        Version::HTTP_2
    );
    assert_eq!(
        determine_http_version(Some(&backend_http2), Version::HTTP_2, false),
        Version::HTTP_2
    );

    // Test with explicit http11 config
    assert_eq!(
        determine_http_version(Some(&backend_http11), Version::HTTP_2, false),
        Version::HTTP_11
    );
    assert_eq!(
        determine_http_version(Some(&backend_http11), Version::HTTP_11, false),
        Version::HTTP_11
    );

    // Test with preserve config
    assert_eq!(
        determine_http_version(Some(&backend_preserve), Version::HTTP_2, false),
        Version::HTTP_2
    );
    assert_eq!(
        determine_http_version(Some(&backend_preserve), Version::HTTP_11, false),
        Version::HTTP_11
    );
    // HTTP/3 should be converted to HTTP/2
    assert_eq!(
        determine_http_version(Some(&backend_preserve), Version::HTTP_3, false),
        Version::HTTP_2
    );
}

#[test]
fn test_determine_http_version_defaults() {
    let backend_no_config =
        Backend { address: "backend:9000".to_string(), http_version: None, health_check: None };

    // Default for HTTP (non-HTTPS): HTTP/1.1
    assert_eq!(
        determine_http_version(Some(&backend_no_config), Version::HTTP_2, false),
        Version::HTTP_11
    );
    assert_eq!(
        determine_http_version(Some(&backend_no_config), Version::HTTP_11, false),
        Version::HTTP_11
    );

    // Default for HTTPS: preserve
    assert_eq!(
        determine_http_version(Some(&backend_no_config), Version::HTTP_2, true),
        Version::HTTP_2
    );
    assert_eq!(
        determine_http_version(Some(&backend_no_config), Version::HTTP_11, true),
        Version::HTTP_11
    );
}

#[test]
fn test_determine_http_version_no_backend() {
    assert_eq!(determine_http_version(None, Version::HTTP_2, false), Version::HTTP_11);
    assert_eq!(determine_http_version(None, Version::HTTP_2, true), Version::HTTP_2);
}

#[test]
fn test_pick_route() {
    let routes = vec![
        Route {
            prefix: "/api".to_string(),
            backend: "backend-a:9000".to_string(),
            fingerprinting: true,
            replace_path: None,
            rate_limit: None,
            headers: None,
            force_new_connection: false,
        },
        Route {
            prefix: "/static".to_string(),
            backend: "backend-b:9000".to_string(),
            fingerprinting: true,
            replace_path: None,
            rate_limit: None,
            headers: None,
            force_new_connection: false,
        },
        Route {
            prefix: "/".to_string(),
            backend: "backend-c:9000".to_string(),
            fingerprinting: true,
            replace_path: None,
            rate_limit: None,
            headers: None,
            force_new_connection: false,
        },
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
    use huginn_proxy_lib::proxy::forwarding::pick_route_with_fingerprinting;

    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend-a:9000".to_string(),
        fingerprinting: true,
        replace_path: None,
        rate_limit: None,
        headers: None,
        force_new_connection: false,
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(route) = result {
        assert_eq!(route.backend, "backend-a:9000");
        assert_eq!(route.backend_candidates, vec!["backend-a:9000"]);
        assert!(route.fingerprinting);
        assert_eq!(route.matched_prefix, "/api");
        assert!(route.replace_path.is_none());
    }
}

#[test]
fn test_pick_route_with_fingerprinting_with_replace_path() {
    use huginn_proxy_lib::proxy::forwarding::pick_route_with_fingerprinting;

    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend-a:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("/v1".to_string()),
        rate_limit: None,
        headers: None,
        force_new_connection: false,
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(route) = result {
        assert_eq!(route.backend, "backend-a:9000");
        assert_eq!(route.backend_candidates, vec!["backend-a:9000"]);
        assert!(route.fingerprinting);
        assert_eq!(route.matched_prefix, "/api");
        assert_eq!(route.replace_path, Some("/v1"));
    }
}

#[test]
fn test_pick_route_with_fingerprinting_path_stripping() {
    use huginn_proxy_lib::proxy::forwarding::pick_route_with_fingerprinting;

    // Path stripping: replace_path = "" or "/"
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend-a:9000".to_string(),
        fingerprinting: false,
        replace_path: Some("".to_string()),
        rate_limit: None, // Strip prefix
        headers: None,
        force_new_connection: false,
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(route) = result {
        assert_eq!(route.backend, "backend-a:9000");
        assert_eq!(route.backend_candidates, vec!["backend-a:9000"]);
        assert!(!route.fingerprinting);
        assert_eq!(route.matched_prefix, "/api");
        assert_eq!(route.replace_path, Some(""));
    }
}

#[test]
fn test_pick_route_with_fingerprinting_collects_same_prefix_candidates() {
    use huginn_proxy_lib::proxy::forwarding::pick_route_with_fingerprinting;

    let routes = vec![
        Route {
            prefix: "/api".to_string(),
            backend: "backend-a:9000".to_string(),
            fingerprinting: true,
            replace_path: None,
            rate_limit: None,
            headers: None,
            force_new_connection: false,
        },
        Route {
            prefix: "/api".to_string(),
            backend: "backend-b:9000".to_string(),
            fingerprinting: true,
            replace_path: None,
            rate_limit: None,
            headers: None,
            force_new_connection: false,
        },
        Route {
            prefix: "/".to_string(),
            backend: "backend-c:9000".to_string(),
            fingerprinting: true,
            replace_path: None,
            rate_limit: None,
            headers: None,
            force_new_connection: false,
        },
    ];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(route) = result {
        assert_eq!(route.matched_prefix, "/api");
        assert_eq!(route.backend, "backend-a:9000");
        assert_eq!(route.backend_candidates, vec!["backend-a:9000", "backend-b:9000"]);
    }
}

#[test]
fn longest_prefix_wins_over_declaration_order() {
    // Bug regression: first-match would send /api/e2e-unhealthy to backend-a instead of unreachable.
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
    // /api must NOT match /api2 — boundary check ensures the segment ends at '/'.
    let routes = sorted_routes(vec![route("/api", "backend-a:9000"), route("/api2", "backend-b:9000")]);
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
