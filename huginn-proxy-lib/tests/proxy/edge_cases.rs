use http::Version;
use huginn_proxy_lib::config::{Backend, BackendHttpVersion, Route};
use huginn_proxy_lib::proxy::forwarding::{
    determine_http_version, find_backend_config, pick_route,
};

#[test]
fn test_pick_route_no_match() {
    let routes = vec![
        Route {
            prefix: "/api".to_string(),
            backend: "backend-a:9000".to_string(),
            fingerprinting: true,
        },
        Route {
            prefix: "/static".to_string(),
            backend: "backend-b:9000".to_string(),
            fingerprinting: true,
        },
    ];

    assert_eq!(pick_route("/unknown/path", &routes), None);
}

#[test]
fn test_pick_route_exact_match() {
    let routes = vec![
        Route {
            prefix: "/api".to_string(),
            backend: "backend-a:9000".to_string(),
            fingerprinting: true,
        },
        Route {
            prefix: "/".to_string(),
            backend: "backend-b:9000".to_string(),
            fingerprinting: true,
        },
    ];

    // Exact match should work
    assert_eq!(pick_route("/api", &routes), Some("backend-a:9000"));
}

#[test]
fn test_pick_route_longest_prefix() {
    let routes = vec![
        Route {
            prefix: "/api/v1".to_string(),
            backend: "backend-v1:9000".to_string(),
            fingerprinting: true,
        },
        Route {
            prefix: "/api".to_string(),
            backend: "backend-api:9000".to_string(),
            fingerprinting: true,
        },
        Route {
            prefix: "/".to_string(),
            backend: "backend-default:9000".to_string(),
            fingerprinting: true,
        },
    ];

    assert_eq!(pick_route("/api/v1/users", &routes), Some("backend-v1:9000"));
}

#[test]
fn test_find_backend_config_case_sensitive() {
    let backends = vec![Backend { address: "Backend-A:9000".to_string(), http_version: None }];

    assert_eq!(
        find_backend_config("backend-a:9000", &backends).map(|b| b.address.as_str()),
        None
    );
    assert_eq!(
        find_backend_config("Backend-A:9000", &backends).map(|b| b.address.as_str()),
        Some("Backend-A:9000")
    );
}

#[test]
fn test_determine_http_version_http3_conversion() {
    let backend_preserve = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Preserve),
    };

    assert_eq!(
        determine_http_version(Some(&backend_preserve), Version::HTTP_3, false),
        Version::HTTP_2
    );
    assert_eq!(
        determine_http_version(Some(&backend_preserve), Version::HTTP_3, true),
        Version::HTTP_2
    );
}

#[test]
fn test_determine_http_version_unknown_version() {
    let backend_preserve = Backend {
        address: "backend:9000".to_string(),
        http_version: Some(BackendHttpVersion::Preserve),
    };

    let result = determine_http_version(Some(&backend_preserve), Version::HTTP_11, false);
    assert!(matches!(result, Version::HTTP_11 | Version::HTTP_2));
}

#[test]
fn test_pick_route_with_empty_prefix() {
    let routes = vec![Route {
        prefix: "".to_string(),
        backend: "backend-default:9000".to_string(),
        fingerprinting: true,
    }];

    assert_eq!(pick_route("/any/path", &routes), Some("backend-default:9000"));
    assert_eq!(pick_route("/", &routes), Some("backend-default:9000"));
}

#[test]
fn test_find_backend_config_with_port_variations() {
    let backends = vec![
        Backend { address: "localhost:9000".to_string(), http_version: None },
        Backend { address: "127.0.0.1:9000".to_string(), http_version: None },
    ];

    assert_eq!(
        find_backend_config("localhost:9000", &backends).map(|b| b.address.as_str()),
        Some("localhost:9000")
    );
    assert_eq!(
        find_backend_config("127.0.0.1:9000", &backends).map(|b| b.address.as_str()),
        Some("127.0.0.1:9000")
    );
    assert_eq!(
        find_backend_config("localhost:8080", &backends).map(|b| b.address.as_str()),
        None
    );
}
