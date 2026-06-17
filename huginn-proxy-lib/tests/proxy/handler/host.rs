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

fn req_h1_absolute(uri: &str) -> http::Request<()> {
    http::Request::builder()
        .method("GET")
        .version(http::Version::HTTP_11)
        .uri(uri)
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
    assert_eq!(extract_request_host_inner(&req), "example.com");
}

#[test]
fn h1_extracts_ipv4_from_host_header() {
    let req = req_h1("127.0.0.1:7000");
    assert_eq!(extract_request_host_inner(&req), "127.0.0.1");
}

#[test]
fn h1_strips_brackets_from_ipv6_host_header() {
    let req = req_h1("[::1]:7000");
    assert_eq!(extract_request_host_inner(&req), "::1");
}

#[test]
fn h1_host_header_without_port() {
    let req = req_h1("api.example.com");
    assert_eq!(extract_request_host_inner(&req), "api.example.com");
}

#[test]
fn h2_extracts_hostname_from_uri_authority() {
    let req = req_h2("https://example.com/path");
    assert_eq!(extract_request_host_inner(&req), "example.com");
}

#[test]
fn h2_extracts_ipv4_from_uri_authority() {
    let req = req_h2("https://127.0.0.1:7000/");
    assert_eq!(extract_request_host_inner(&req), "127.0.0.1");
}

#[test]
fn h2_strips_brackets_from_ipv6_uri_authority() {
    // http::Uri::host() returns "[::1]" for IPv6; strip_host_port normalises it.
    let req = req_h2("https://[::1]:7000/");
    assert_eq!(extract_request_host_inner(&req), "::1");
}

#[test]
fn h2_uri_authority_wins_over_spoofed_host_header() {
    // Client sets a forged Host header, :authority takes priority.
    let req = req_h2_with_host("https://127.0.0.1:7000/", "evil.example.com");
    assert_eq!(extract_request_host_inner(&req), "127.0.0.1");
}

#[test]
fn h2_authority_wins_on_coalesced_connection() {
    // HTTP/2 multiplexes many requests over one connection. A browser may connect
    // with SNI="api.example.com" but send a request with :authority="docs.example.com"
    // (valid when one cert covers both via wildcard). Routing follows :authority, not
    // the connection-level SNI, SNI is never a routing input.
    let req = req_h2("https://docs.example.com/");
    assert_eq!(extract_request_host_inner(&req), "docs.example.com");
}

#[test]
fn h1_routes_by_host_header_not_sni() {
    // HTTP/1.1 routes by the Host header (RFC 7230 §5.4), consistent with HTTP/2 and
    // with nginx/Traefik. SNI is only for cert selection at the TLS layer, never routing.
    let req = req_h1("docs.example.com");
    assert_eq!(extract_request_host_inner(&req), "docs.example.com");
}

#[test]
fn h1_absolute_form_authority_wins_over_host_header() {
    // HTTP/1.1 absolute-form request target (RFC 7230 §5.3.2): the URI authority is used.
    let req = http::Request::builder()
        .method("GET")
        .version(http::Version::HTTP_11)
        .uri("https://authority.example.com/path")
        .header("Host", "header.example.com")
        .body(())
        .unwrap_or_else(|_| http::Request::new(()));
    assert_eq!(extract_request_host_inner(&req), "authority.example.com");
}

#[test]
fn ip_connection_routes_by_uri_authority() {
    // IP connections don't send SNI (RFC 6066); routing uses :authority / Host as usual.
    let req = req_h2("https://127.0.0.1:7000/");
    assert_eq!(extract_request_host_inner(&req), "127.0.0.1");
}

#[test]
fn h2_ipv6_authority_is_extracted() {
    let req = req_h2("https://[::1]:7000/");
    assert_eq!(extract_request_host_inner(&req), "::1");
}

#[test]
fn origin_form_uri_with_no_host_header_returns_empty() {
    // No Host header, no URI authority, can't determine host.
    let req = http::Request::builder()
        .method("GET")
        .uri("/path")
        .body(())
        .unwrap_or_else(|_| http::Request::new(()));
    assert_eq!(extract_request_host_inner(&req), "");
}

#[test]
fn h1_host_header_ipv6_without_port() {
    let req = req_h1("[2001:db8::1]");
    assert_eq!(extract_request_host_inner(&req), "2001:db8::1");
}

#[test]
fn host_header_is_lowercased() {
    // RFC 7230: Host is case-insensitive. We lowercase so it matches lowercased config.
    let req = req_h1("API.Example.COM:8080");
    assert_eq!(extract_request_host_inner(&req), "api.example.com");
}

#[test]
fn uri_authority_is_lowercased() {
    let req = req_h2("https://EXAMPLE.com/path");
    assert_eq!(extract_request_host_inner(&req), "example.com");
}

#[test]
fn h2_wildcard_connection_reuse_routes_correctly() {
    // Scenario: proxy serves *.example.com with one wildcard cert.
    // Browser connects with SNI="api.example.com", then reuses the H/2 connection
    // (RFC 9113 §9.1.1) to send a second request with :authority="docs.example.com".
    // Routing follows :authority → request reaches "docs.example.com" correctly.
    let req = req_h2("https://docs.example.com/help");
    assert_eq!(extract_request_host_inner(&req), "docs.example.com");
}

#[test]
fn h2_falls_back_to_host_header_when_authority_absent() {
    // HTTP/2 without :authority falls through to the Host header.
    // (In practice H/2 without :authority is malformed, but we degrade gracefully.)
    let req = http::Request::builder()
        .method("GET")
        .version(http::Version::HTTP_2)
        .uri("/path")
        .header("Host", "fallback.example.com")
        .body(())
        .unwrap_or_else(|_| http::Request::new(()));
    assert_eq!(extract_request_host_inner(&req), "fallback.example.com");
}

#[test]
fn plain_http_routes_by_host_header() {
    // Plain HTTP/1.1 (no TLS, no SNI): routes by Host header.
    let req = req_h1_absolute("http://plain.example.com/x");
    assert_eq!(extract_request_host_inner(&req), "plain.example.com");
}
