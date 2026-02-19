use http::Version;
use huginn_proxy_lib::config::{Backend, BackendHttpVersion, Route};
use huginn_proxy_lib::proxy::forwarding::{
    determine_http_version, find_backend_config, pick_route,
};

#[test]
fn test_find_backend_config() {
    let backends = vec![
        Backend {
            address: "backend-a:9000".to_string(),
            http_version: Some(BackendHttpVersion::Http2),
        },
        Backend {
            address: "backend-b:9000".to_string(),
            http_version: Some(BackendHttpVersion::Http11),
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
    };
    let backend_http11 = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Http11),
    };
    let backend_preserve = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Preserve),
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
    let backend_no_config = Backend { address: "backend:9000".to_string(), http_version: None };

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
        assert!(!route.fingerprinting);
        assert_eq!(route.matched_prefix, "/api");
        assert_eq!(route.replace_path, Some(""));
    }
}
