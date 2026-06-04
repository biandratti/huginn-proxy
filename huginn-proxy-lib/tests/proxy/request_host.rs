use huginn_proxy_lib::proxy::handler::{extract_request_host_inner, strip_host_port};

#[test]
fn strip_port_from_hostname() {
    assert_eq!(strip_host_port("example.com:8080"), "example.com");
}

#[test]
fn hostname_without_port_is_unchanged() {
    assert_eq!(strip_host_port("example.com"), "example.com");
}

#[test]
fn strip_port_from_ipv4() {
    assert_eq!(strip_host_port("127.0.0.1:7000"), "127.0.0.1");
}

#[test]
fn ipv4_without_port_is_unchanged() {
    assert_eq!(strip_host_port("127.0.0.1"), "127.0.0.1");
}

#[test]
fn strip_brackets_and_port_from_ipv6() {
    assert_eq!(strip_host_port("[::1]:8080"), "::1");
}

#[test]
fn strip_brackets_from_ipv6_no_port() {
    assert_eq!(strip_host_port("[::1]"), "::1");
}

#[test]
fn strip_brackets_from_full_ipv6() {
    assert_eq!(strip_host_port("[2001:db8::1]:443"), "2001:db8::1");
}

#[test]
fn strip_port_from_localhost() {
    assert_eq!(strip_host_port("localhost:3000"), "localhost");
}

#[test]
fn empty_string_returns_empty() {
    assert_eq!(strip_host_port(""), "");
}

fn req_h1(host_header: &str) -> http::Request<()> {
    http::Request::builder()
        .method("GET")
        .uri("/")
        .header("Host", host_header)
        .body(())
        .unwrap_or_else(|_| http::Request::new(()))
}

fn req_h2(uri: &str) -> http::Request<()> {
    http::Request::builder()
        .method("GET")
        .version(http::Version::HTTP_2)
        .uri(uri)
        .body(())
        .unwrap_or_else(|_| http::Request::new(()))
}

fn req_h2_with_host(uri: &str, host: &str) -> http::Request<()> {
    http::Request::builder()
        .method("GET")
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header("Host", host)
        .body(())
        .unwrap_or_else(|_| http::Request::new(()))
}

#[test]
fn h1_extracts_hostname_from_host_header() {
    let req = req_h1("example.com:8080");
    assert_eq!(extract_request_host_inner(&req, None, false), "example.com");
}

#[test]
fn h1_extracts_ipv4_from_host_header() {
    let req = req_h1("127.0.0.1:7000");
    assert_eq!(extract_request_host_inner(&req, None, false), "127.0.0.1");
}

#[test]
fn h1_strips_brackets_from_ipv6_host_header() {
    let req = req_h1("[::1]:7000");
    assert_eq!(extract_request_host_inner(&req, None, false), "::1");
}

#[test]
fn h1_host_header_without_port() {
    let req = req_h1("api.example.com");
    assert_eq!(extract_request_host_inner(&req, None, false), "api.example.com");
}

#[test]
fn h2_extracts_hostname_from_uri_authority() {
    let req = req_h2("https://example.com/path");
    assert_eq!(extract_request_host_inner(&req, None, true), "example.com");
}

#[test]
fn h2_extracts_ipv4_from_uri_authority() {
    let req = req_h2("https://127.0.0.1:7000/");
    assert_eq!(extract_request_host_inner(&req, None, false), "127.0.0.1");
}

#[test]
fn h2_strips_brackets_from_ipv6_uri_authority() {
    // http::Uri::host() returns "[::1]" for IPv6; strip_host_port normalises it.
    let req = req_h2("https://[::1]:7000/");
    assert_eq!(extract_request_host_inner(&req, None, false), "::1");
}

#[test]
fn h2_uri_authority_wins_over_spoofed_host_header() {
    // Client sets a forged Host header, URI authority takes priority.
    let req = req_h2_with_host("https://127.0.0.1:7000/", "evil.example.com");
    assert_eq!(extract_request_host_inner(&req, None, false), "127.0.0.1");
}

#[test]
fn tls_sni_takes_priority_over_uri_authority() {
    let req = req_h2("https://127.0.0.1:7000/");
    assert_eq!(
        extract_request_host_inner(&req, Some("api.example.com"), true),
        "api.example.com"
    );
}

#[test]
fn tls_sni_not_used_when_is_https_false() {
    // SNI present but is_https=false → ignored, falls through to Host header.
    let req = req_h1("127.0.0.1:7000");
    assert_eq!(extract_request_host_inner(&req, Some("api.example.com"), false), "127.0.0.1");
}

#[test]
fn no_sni_falls_through_to_uri_authority() {
    // IP connections don't send SNI (RFC 6066) → falls through to URI authority.
    let req = req_h2("https://127.0.0.1:7000/");
    assert_eq!(extract_request_host_inner(&req, None, true), "127.0.0.1");
}

#[test]
fn tls_sni_takes_priority_over_ipv6_uri() {
    let req = req_h2("https://[::1]:7000/");
    assert_eq!(
        extract_request_host_inner(&req, Some("api.example.com"), true),
        "api.example.com"
    );
}

#[test]
fn origin_form_uri_with_no_host_header_returns_empty() {
    // No Host header, no URI authority, can't determine host.
    let req = http::Request::builder()
        .method("GET")
        .uri("/path")
        .body(())
        .unwrap_or_else(|_| http::Request::new(()));
    assert_eq!(extract_request_host_inner(&req, None, false), "");
}

#[test]
fn h1_host_header_ipv6_without_port() {
    let req = req_h1("[2001:db8::1]");
    assert_eq!(extract_request_host_inner(&req, None, false), "2001:db8::1");
}
