use http::HeaderMap;
use huginn_proxy_lib::fingerprinting::names;
use huginn_proxy_lib::proxy::handler::request::strip_client_fingerprints;
use hyper::header::{HeaderName, HeaderValue};

#[test]
fn strip_single_fingerprint_header() {
    for &name in names::FINGERPRINTS {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static(name), HeaderValue::from_static("forged"));
        let spoofed = strip_client_fingerprints(&mut headers);
        assert_eq!(spoofed, vec![name], "should detect {name} as spoofed");
        assert!(!headers.contains_key(name), "{name} should be stripped from headers");
    }
}

#[test]
fn strip_multiple_fingerprint_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(names::HTTP2_AKAMAI),
        HeaderValue::from_static("FORGED-AKAMAI"),
    );
    headers.insert(HeaderName::from_static(names::TCP_SYN), HeaderValue::from_static("FORGED-TCP"));
    headers.insert(HeaderName::from_static(names::TLS_JA4), HeaderValue::from_static("FORGED-JA4"));
    let spoofed = strip_client_fingerprints(&mut headers);
    assert!(spoofed.contains(&names::HTTP2_AKAMAI));
    assert!(spoofed.contains(&names::TCP_SYN));
    assert!(spoofed.contains(&names::TLS_JA4));
    assert_eq!(spoofed.len(), 3);
    assert!(!headers.contains_key(names::HTTP2_AKAMAI));
    assert!(!headers.contains_key(names::TCP_SYN));
    assert!(!headers.contains_key(names::TLS_JA4));
}

#[test]
fn strip_no_fingerprint_headers_leaves_others() {
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("x-custom"), HeaderValue::from_static("value"));
    let spoofed = strip_client_fingerprints(&mut headers);
    assert!(spoofed.is_empty());
    assert!(!headers.contains_key(names::SPOOFING_DETECTED));
    assert!(headers.contains_key("x-custom"), "non-fingerprint headers must be untouched");
}

#[test]
fn strip_detection_header_only_yields_empty_list() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(names::SPOOFING_DETECTED),
        HeaderValue::from_static(names::TLS_JA4),
    );
    let spoofed = strip_client_fingerprints(&mut headers);
    assert!(spoofed.is_empty(), "SPOOFING_DETECTED is not a fingerprint signature");
    assert!(!headers.contains_key(names::SPOOFING_DETECTED));
}

#[test]
fn forged_detection_header_does_not_appear_in_spoofed_list() {
    let mut headers = HeaderMap::new();
    // attacker tries to say "nothing is wrong"
    headers.insert(
        HeaderName::from_static(names::SPOOFING_DETECTED),
        HeaderValue::from_static("false"),
    );
    headers
        .insert(HeaderName::from_static(names::HTTP2_AKAMAI), HeaderValue::from_static("FORGED"));
    let spoofed = strip_client_fingerprints(&mut headers);
    assert_eq!(spoofed, vec![names::HTTP2_AKAMAI]);
    assert!(!headers.contains_key(names::SPOOFING_DETECTED));
    assert!(!headers.contains_key(names::HTTP2_AKAMAI));
}

#[test]
fn strip_fingerprint_headers_case_insensitive() {
    let mut headers = HeaderMap::new();
    if let Ok(name) = HeaderName::from_bytes(b"X-TLS-JA4") {
        headers.insert(name, HeaderValue::from_static("FORGED"));
    }
    let spoofed = strip_client_fingerprints(&mut headers);
    assert_eq!(spoofed, vec![names::TLS_JA4]);
    assert!(!headers.contains_key(names::TLS_JA4));
}

#[test]
fn strip_multivalue_fingerprint_header() {
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static(names::TLS_JA4);
    headers.insert(name.clone(), HeaderValue::from_static("FORGED-1"));
    headers.append(name, HeaderValue::from_static("FORGED-2"));
    let spoofed = strip_client_fingerprints(&mut headers);
    assert_eq!(spoofed, vec![names::TLS_JA4]);
    assert!(!headers.contains_key(names::TLS_JA4));
}

#[test]
fn fingerprints_list_covers_all_authoritative_headers() {
    use std::collections::HashSet;
    let expected: HashSet<&str> = [
        names::TLS_JA4,
        names::TLS_JA4_R,
        names::TLS_JA4_O,
        names::TLS_JA4_OR,
        names::TLS_JA4_S1,
        names::TLS_JA4_S1R,
        names::HTTP2_AKAMAI,
        names::TCP_SYN,
    ]
    .into_iter()
    .collect();
    let actual: HashSet<&str> = names::FINGERPRINTS.iter().copied().collect();
    assert_eq!(
        actual, expected,
        "names::FINGERPRINTS must contain exactly the 8 proxy-authoritative fingerprint headers"
    );
}
