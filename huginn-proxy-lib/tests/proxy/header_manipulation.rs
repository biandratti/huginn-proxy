use http::{HeaderMap, HeaderValue};
use huginn_proxy_lib::proxy::handler::header_manipulation::{add_headers, remove_headers};

#[test]
fn test_remove_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("server", HeaderValue::from_static("nginx"));
    headers.insert("x-powered-by", HeaderValue::from_static("PHP/8.0"));
    headers.insert("x-custom", HeaderValue::from_static("keep-me"));

    remove_headers(
        &mut headers,
        &["server".to_string(), "x-powered-by".to_string()],
    );

    assert!(headers.get("server").is_none());
    assert!(headers.get("x-powered-by").is_none());
    assert!(headers.get("x-custom").is_some());
}

#[test]
fn test_remove_headers_case_insensitive() {
    let mut headers = HeaderMap::new();
    headers.insert("server", HeaderValue::from_static("nginx"));

    // Should work with different case
    remove_headers(&mut headers, &["SERVER".to_string()]);

    assert!(headers.get("server").is_none());
}

#[test]
fn test_remove_headers_nonexistent() {
    let mut headers = HeaderMap::new();
    headers.insert("server", HeaderValue::from_static("nginx"));

    // Should not panic if header doesn't exist
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

    // Invalid header name (contains space)
    let to_add = vec![("invalid name".to_string(), "value".to_string())];

    add_headers(&mut headers, &to_add);

    // Should not panic, just log warning
    assert!(headers.get("invalid name").is_none());
}

#[test]
fn test_add_headers_invalid_value() {
    let mut headers = HeaderMap::new();

    // Invalid header value (contains newline)
    let to_add = vec![("x-custom".to_string(), "value\nwith\nnewlines".to_string())];

    add_headers(&mut headers, &to_add);

    // Should not panic, just log warning
    assert!(headers.get("x-custom").is_none());
}
