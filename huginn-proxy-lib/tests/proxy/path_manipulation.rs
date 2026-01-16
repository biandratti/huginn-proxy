// Tests for path stripping and rewriting functionality
use huginn_proxy_lib::config::Route;
use huginn_proxy_lib::proxy::forwarding::pick_route_with_fingerprinting;

#[test]
fn test_path_stripping_basic() {
    // Test case copied from rust-rpxy example:
    // Request: /api/users → Backend: /users (strip /api prefix)
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("".to_string()), // Empty string means strip prefix
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/api");
        assert_eq!(replace_path, &Some("".to_string()));
    }
}

#[test]
fn test_path_stripping_with_query_params() {
    // Verify that query parameters are preserved during path stripping
    // Request: /api/users?id=123 → Backend: /users?id=123
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("".to_string()),
    }];

    let result = pick_route_with_fingerprinting("/api/users?id=123&name=test", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/api");
        assert_eq!(replace_path, &Some("".to_string()));
        // Note: Query parameter preservation is tested in integration tests
    }
}

#[test]
fn test_path_rewriting_basic() {
    // Test case from rust-rpxy config-example.toml:
    // path = '/maps', replace_path = "/replacing/path1"
    // Request: /maps/org/any.ext → Backend: /replacing/path1/org/any.ext
    let routes = vec![Route {
        prefix: "/maps".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("/replacing/path1".to_string()),
    }];

    let result = pick_route_with_fingerprinting("/maps/org/any.ext", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/maps");
        assert_eq!(replace_path, &Some("/replacing/path1".to_string()));
    }
}

#[test]
fn test_path_rewriting_with_versioned_api() {
    // Real-world use case: rewrite /api to /v1/api
    // Request: /api/users → Backend: /v1/api/users
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("/v1/api".to_string()),
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/api");
        assert_eq!(replace_path, &Some("/v1/api".to_string()));
    }
}

#[test]
fn test_no_path_manipulation() {
    // When replace_path is None, path should be forwarded as-is
    // Request: /api/users → Backend: /api/users (no changes)
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: None,
    }];

    let result = pick_route_with_fingerprinting("/api/users", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/api");
        assert!(replace_path.is_none());
    }
}

#[test]
fn test_path_manipulation_with_nested_paths() {
    // Test with nested paths: /api/v1/users
    let routes = vec![Route {
        prefix: "/api/v1".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("/backend/v1".to_string()),
    }];

    let result = pick_route_with_fingerprinting("/api/v1/users/123", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/api/v1");
        assert_eq!(replace_path, &Some("/backend/v1".to_string()));
    }
}

#[test]
fn test_path_manipulation_root_path() {
    // Test with root path: / → /api
    let routes = vec![Route {
        prefix: "/".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("/api".to_string()),
    }];

    let result = pick_route_with_fingerprinting("/users", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/");
        assert_eq!(replace_path, &Some("/api".to_string()));
    }
}

#[test]
fn test_multiple_routes_matching_priority() {
    // Test that the first matching route wins
    // Copied from rust-rpxy's PathManager::get() logic
    let routes = vec![
        Route {
            prefix: "/api/v1".to_string(),
            backend: "backend-v1:9000".to_string(),
            fingerprinting: true,
            replace_path: Some("/v1".to_string()),
        },
        Route {
            prefix: "/api".to_string(),
            backend: "backend-api:9000".to_string(),
            fingerprinting: true,
            replace_path: Some("/".to_string()),
        },
    ];

    // Should match the more specific route first (/api/v1)
    let result = pick_route_with_fingerprinting("/api/v1/users", &routes);
    assert!(result.is_some());

    if let Some((backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(backend, "backend-v1:9000");
        assert_eq!(prefix, "/api/v1");
        assert_eq!(replace_path, &Some("/v1".to_string()));
    }
}

#[test]
fn test_path_manipulation_exact_prefix_match() {
    // Test when request path exactly matches prefix
    // Request: /api → Backend: /v1
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("/v1".to_string()),
    }];

    let result = pick_route_with_fingerprinting("/api", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/api");
        assert_eq!(replace_path, &Some("/v1".to_string()));
    }
}

#[test]
fn test_path_stripping_to_root() {
    // Strip prefix and forward to root
    // Request: /api/health → Backend: /health
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("".to_string()),
    }];

    let result = pick_route_with_fingerprinting("/api/health", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/api");
        assert_eq!(replace_path, &Some("".to_string()));
    }
}

#[test]
fn test_path_manipulation_with_special_characters() {
    // Test with special characters in path
    // Request: /api/users%20info → Backend: /v1/users%20info
    let routes = vec![Route {
        prefix: "/api".to_string(),
        backend: "backend:9000".to_string(),
        fingerprinting: true,
        replace_path: Some("/v1".to_string()),
    }];

    let result = pick_route_with_fingerprinting("/api/users%20info", &routes);
    assert!(result.is_some());

    if let Some((_backend, _fingerprinting, prefix, replace_path)) = result {
        assert_eq!(prefix, "/api");
        assert_eq!(replace_path, &Some("/v1".to_string()));
    }
}
