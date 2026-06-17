use http::{HeaderMap, HeaderValue};
use huginn_proxy_lib::config::{CustomHeader, HeaderManipulation, HeaderManipulationGroup};
use huginn_proxy_lib::proxy::handler::header_manipulation::{
    add_headers, apply_request_header_manipulation, apply_response_header_manipulation,
    remove_headers,
};
use huginn_proxy_lib::telemetry::Metrics;

/// Build a `HeaderManipulation` whose request+response both add `name: value`.
fn add_both(name: &str, value: &str) -> HeaderManipulation {
    let group = HeaderManipulationGroup {
        add: vec![CustomHeader { name: name.to_string(), value: value.to_string() }],
        remove: vec![],
    };
    HeaderManipulation { request: group.clone(), response: group }
}

#[test]
fn test_remove_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("server", HeaderValue::from_static("nginx"));
    headers.insert("x-powered-by", HeaderValue::from_static("PHP/8.0"));
    headers.insert("x-custom", HeaderValue::from_static("keep-me"));

    remove_headers(&mut headers, &["server".to_string(), "x-powered-by".to_string()]);

    assert!(headers.get("server").is_none());
    assert!(headers.get("x-powered-by").is_none());
    assert!(headers.get("x-custom").is_some());
}

#[test]
fn test_remove_headers_case_insensitive() {
    let mut headers = HeaderMap::new();
    headers.insert("server", HeaderValue::from_static("nginx"));

    remove_headers(&mut headers, &["SERVER".to_string()]);

    assert!(headers.get("server").is_none());
}

#[test]
fn test_remove_headers_nonexistent() {
    let mut headers = HeaderMap::new();
    headers.insert("server", HeaderValue::from_static("nginx"));

    remove_headers(&mut headers, &["nonexistent".to_string()]);

    assert!(headers.get("server").is_some());
}

#[test]
fn test_add_headers() {
    let mut headers = HeaderMap::new();

    let to_add = vec![
        ("x-custom".to_string(), "value1".to_string()),
        ("x-another".to_string(), "value2".to_string()),
    ];

    add_headers(&mut headers, &to_add);

    assert_eq!(headers.get("x-custom").map(|v| v.as_bytes()), Some(b"value1".as_ref()));
    assert_eq!(headers.get("x-another").map(|v| v.as_bytes()), Some(b"value2".as_ref()));
}

#[test]
fn test_add_headers_overwrite() {
    let mut headers = HeaderMap::new();
    headers.insert("x-custom", HeaderValue::from_static("old-value"));

    let to_add = vec![("x-custom".to_string(), "new-value".to_string())];

    add_headers(&mut headers, &to_add);
    assert_eq!(headers.get("x-custom").map(|v| v.as_bytes()), Some(b"new-value".as_ref()));
}

#[test]
fn test_add_headers_invalid_name() {
    let mut headers = HeaderMap::new();

    let to_add = vec![("invalid name".to_string(), "value".to_string())];

    add_headers(&mut headers, &to_add);
    assert!(headers.get("invalid name").is_none());
}

#[test]
fn test_add_headers_invalid_value() {
    let mut headers = HeaderMap::new();

    let to_add = vec![("x-custom".to_string(), "value\nwith\nnewlines".to_string())];

    add_headers(&mut headers, &to_add);
    assert!(headers.get("x-custom").is_none());
}

#[test]
fn request_domain_level_is_applied() {
    // Regression: Domain.headers used to be parsed but never applied.
    let mut headers = HeaderMap::new();
    let domain = add_both("x-proxy", "huginn");

    apply_request_header_manipulation(
        &mut headers,
        None,
        Some(&domain),
        None,
        &Metrics::new_noop(),
    );

    assert_eq!(headers.get("x-proxy").map(|v| v.as_bytes()), Some(b"huginn".as_ref()));
}

#[test]
fn response_domain_level_is_applied() {
    let mut headers = HeaderMap::new();
    let domain = add_both("x-proxy", "huginn");

    apply_response_header_manipulation(
        &mut headers,
        None,
        Some(&domain),
        None,
        &Metrics::new_noop(),
    );

    assert_eq!(headers.get("x-proxy").map(|v| v.as_bytes()), Some(b"huginn".as_ref()));
}

#[test]
fn most_specific_scope_wins_for_same_header() {
    // global → domain → route, all set "x-scope"; route (most specific) must win.
    let mut headers = HeaderMap::new();
    let global = add_both("x-scope", "global");
    let domain = add_both("x-scope", "domain");
    let route = add_both("x-scope", "route");

    apply_request_header_manipulation(
        &mut headers,
        Some(&global),
        Some(&domain),
        Some(&route),
        &Metrics::new_noop(),
    );
    assert_eq!(headers.get("x-scope").map(|v| v.as_bytes()), Some(b"route".as_ref()));

    // With no route scope, the domain value wins over global.
    let mut headers = HeaderMap::new();
    apply_request_header_manipulation(
        &mut headers,
        Some(&global),
        Some(&domain),
        None,
        &Metrics::new_noop(),
    );
    assert_eq!(headers.get("x-scope").map(|v| v.as_bytes()), Some(b"domain".as_ref()));
}

#[test]
fn each_scope_contributes_distinct_headers() {
    let mut headers = HeaderMap::new();
    let global = add_both("x-global", "g");
    let domain = add_both("x-domain", "d");
    let route = add_both("x-route", "r");

    apply_response_header_manipulation(
        &mut headers,
        Some(&global),
        Some(&domain),
        Some(&route),
        &Metrics::new_noop(),
    );

    assert_eq!(headers.get("x-global").map(|v| v.as_bytes()), Some(b"g".as_ref()));
    assert_eq!(headers.get("x-domain").map(|v| v.as_bytes()), Some(b"d".as_ref()));
    assert_eq!(headers.get("x-route").map(|v| v.as_bytes()), Some(b"r".as_ref()));
}
