use http::Response;
use huginn_proxy_lib::config::{CspConfig, CustomHeader, HstsConfig, SecurityHeaders};
use huginn_proxy_lib::security::apply_security_headers;

#[test]
fn test_apply_custom_headers() {
    let config = SecurityHeaders {
        custom: vec![
            CustomHeader { name: "X-Frame-Options".to_string(), value: "DENY".to_string() },
            CustomHeader {
                name: "X-Content-Type-Options".to_string(),
                value: "nosniff".to_string(),
            },
        ],
        hsts: HstsConfig::default(),
        csp: CspConfig::default(),
    };

    let mut response = Response::new("body");
    apply_security_headers(&mut response, Some(&config), false);

    if let Some(header) = response.headers().get("x-frame-options") {
        if let Ok(value) = header.to_str() {
            assert_eq!(value, "DENY");
        } else {
            panic!("Failed to convert header to string");
        }
    } else {
        panic!("Header x-frame-options not found");
    }

    if let Some(header) = response.headers().get("x-content-type-options") {
        if let Ok(value) = header.to_str() {
            assert_eq!(value, "nosniff");
        } else {
            panic!("Failed to convert header to string");
        }
    } else {
        panic!("Header x-content-type-options not found");
    }
}

#[test]
fn test_hsts_header_https_only() {
    let config = SecurityHeaders {
        custom: vec![],
        hsts: HstsConfig {
            enabled: true,
            max_age: 31536000,
            include_subdomains: true,
            preload: false,
        },
        csp: CspConfig::default(),
    };

    // HSTS should be added for HTTPS
    let mut response_https = Response::new("body");
    apply_security_headers(&mut response_https, Some(&config), true);
    assert!(response_https
        .headers()
        .get("strict-transport-security")
        .is_some());

    // HSTS should NOT be added for HTTP
    let mut response_http = Response::new("body");
    apply_security_headers(&mut response_http, Some(&config), false);
    assert!(response_http
        .headers()
        .get("strict-transport-security")
        .is_none());
}

#[test]
fn test_hsts_header_format() {
    let config = SecurityHeaders {
        custom: vec![],
        hsts: HstsConfig {
            enabled: true,
            max_age: 63072000,
            include_subdomains: true,
            preload: true,
        },
        csp: CspConfig::default(),
    };

    let mut response = Response::new("body");
    apply_security_headers(&mut response, Some(&config), true);

    if let Some(header) = response.headers().get("strict-transport-security") {
        if let Ok(header_str) = header.to_str() {
            assert!(header_str.contains("max-age=63072000"));
            assert!(header_str.contains("includeSubDomains"));
            assert!(header_str.contains("preload"));
        } else {
            panic!("Header should be valid UTF-8");
        }
    } else {
        panic!("strict-transport-security should be set for HTTPS with HSTS enabled");
    }
}

#[test]
fn test_csp_header() {
    let config = SecurityHeaders {
        custom: vec![],
        hsts: HstsConfig::default(),
        csp: CspConfig {
            enabled: true,
            policy: "default-src 'self'; script-src 'self' 'unsafe-inline'".to_string(),
        },
    };

    let mut response = Response::new("body");
    apply_security_headers(&mut response, Some(&config), false);

    if let Some(header) = response.headers().get("content-security-policy") {
        if let Ok(value) = header.to_str() {
            assert_eq!(value, "default-src 'self'; script-src 'self' 'unsafe-inline'");
        } else {
            panic!("Failed to convert CSP header to string");
        }
    } else {
        panic!("CSP header not found");
    }
}

#[test]
fn test_no_config() {
    let mut response = Response::new("body");
    apply_security_headers(&mut response, None, false);

    // No headers should be added
    assert!(response.headers().is_empty());
}

#[test]
fn test_disabled_features() {
    let config = SecurityHeaders {
        custom: vec![],
        hsts: HstsConfig {
            enabled: false,
            max_age: 31536000,
            include_subdomains: true,
            preload: false,
        },
        csp: CspConfig { enabled: false, policy: "default-src 'self'".to_string() },
    };

    let mut response = Response::new("body");
    apply_security_headers(&mut response, Some(&config), true);

    // No headers should be added when features are disabled
    assert!(response.headers().is_empty());
}
