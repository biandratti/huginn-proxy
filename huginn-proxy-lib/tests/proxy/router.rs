use huginn_proxy_lib::config::{sort_routes, Route};
use huginn_proxy_lib::proxy::router::{pick_route, pick_route_with_fingerprinting, prefix_matches};

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

fn sorted_routes(mut routes: Vec<Route>) -> Vec<Route> {
    sort_routes(&mut routes);
    routes
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
        assert!(r.fingerprinting);
        assert_eq!(r.matched_prefix, "/api");
        assert!(r.replace_path.is_none());
    }
}

#[test]
fn test_pick_route_with_fingerprinting_with_replace_path() {
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
        fingerprinting: false,
        replace_path: Some("".to_string()),
        rate_limit: None,
        headers: None,
        force_new_connection: false,
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());
    if let Some(r) = result {
        assert!(!r.fingerprinting);
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
