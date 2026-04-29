use http::Version;
use huginn_proxy_lib::config::{Backend, BackendHttpVersion};
use huginn_proxy_lib::proxy::forwarding::{determine_http_version, find_backend_config};

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

    assert_eq!(
        determine_http_version(Some(&backend_http2), Version::HTTP_11, false),
        Version::HTTP_2
    );
    assert_eq!(
        determine_http_version(Some(&backend_http2), Version::HTTP_2, false),
        Version::HTTP_2
    );
    assert_eq!(
        determine_http_version(Some(&backend_http11), Version::HTTP_2, false),
        Version::HTTP_11
    );
    assert_eq!(
        determine_http_version(Some(&backend_http11), Version::HTTP_11, false),
        Version::HTTP_11
    );
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
