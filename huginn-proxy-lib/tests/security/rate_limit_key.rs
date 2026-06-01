use huginn_proxy_lib::config::LimitBy;
use huginn_proxy_lib::security::extract_rate_limit_key;
use ipnet::IpNet;

fn peer(s: &str) -> std::net::SocketAddr {
    s.parse()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
}

fn nets(cidrs: &[&str]) -> Vec<IpNet> {
    cidrs.iter().filter_map(|s| s.parse().ok()).collect()
}

fn headers_with_xff(xff: &str) -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    if let Ok(hv) = http::header::HeaderValue::from_str(xff) {
        h.insert(http::header::HeaderName::from_static("x-forwarded-for"), hv);
    }
    h
}

fn key_ip(peer_addr: std::net::SocketAddr, headers: &http::HeaderMap, proxies: &[IpNet]) -> String {
    extract_rate_limit_key(LimitBy::Ip, peer_addr, "/", None, headers, proxies)
}

#[test]
fn ip_no_trusted_uses_peer() {
    // No trusted_proxies → always peer IP, even with XFF present.
    assert_eq!(key_ip(peer("1.2.3.4:1234"), &headers_with_xff("9.9.9.9"), &[]), "1.2.3.4");
}

#[test]
fn ip_spoof_rotation_pinned_to_peer() {
    // Client rotates XFF values — result never changes without trusted_proxies.
    let proxies: &[IpNet] = &[];
    let p = peer("1.2.3.4:1234");
    for xff in &["10.0.0.1", "172.16.0.1", "203.0.113.5, 10.0.0.1"] {
        assert_eq!(key_ip(p, &headers_with_xff(xff), proxies), "1.2.3.4");
    }
}

#[test]
fn ip_untrusted_peer_ignores_xff() {
    // trusted_proxies is set but the peer itself is NOT in the list → ignore XFF.
    let proxies = nets(&["10.0.0.0/8"]);
    assert_eq!(
        key_ip(peer("8.8.8.8:80"), &headers_with_xff("203.0.113.5"), &proxies),
        "8.8.8.8"
    );
}

#[test]
fn ip_trusted_peer_returns_real_client() {
    // Peer is a trusted LB; XFF contains the real client IP.
    let proxies = nets(&["10.0.0.0/8"]);
    assert_eq!(
        key_ip(peer("10.0.0.1:443"), &headers_with_xff("203.0.113.5"), &proxies),
        "203.0.113.5"
    );
}

#[test]
fn ip_trusted_peer_multi_hop() {
    // Two trusted hops; walk right-to-left past them to reach the real client.
    // XFF: "client, trusted-lb-1, trusted-lb-2"  peer = trusted-lb-3
    let proxies = nets(&["10.0.0.0/8"]);
    let xff = "203.0.113.5, 10.0.0.2, 10.0.0.3";
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies), "203.0.113.5");
}

#[test]
fn ip_trusted_peer_no_xff_falls_back() {
    // Peer is trusted but XFF header is absent → fall back to peer IP.
    let proxies = nets(&["10.0.0.0/8"]);
    assert_eq!(key_ip(peer("10.0.0.1:443"), &http::HeaderMap::new(), &proxies), "10.0.0.1");
}

#[test]
fn ip_trusted_peer_all_xff_trusted() {
    // All XFF entries are also trusted → fall back to peer IP.
    let proxies = nets(&["10.0.0.0/8"]);
    let xff = "10.0.1.1, 10.0.2.2";
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies), "10.0.0.1");
}

#[test]
fn ip_malformed_xff_falls_back() {
    // Unparseable XFF entries are skipped; if all fail, fall back to peer IP.
    let proxies = nets(&["10.0.0.0/8"]);
    assert_eq!(
        key_ip(peer("10.0.0.1:443"), &headers_with_xff("not-an-ip"), &proxies),
        "10.0.0.1"
    );
}

#[test]
fn ip_xff_with_spaces() {
    // Spaces around the comma separator must be trimmed.
    let proxies = nets(&["10.0.0.0/8"]);
    let xff = "  203.0.113.5  ,  10.0.0.2  ";
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies), "203.0.113.5");
}

#[test]
fn ipv6_trusted_peer() {
    let proxies = nets(&["fc00::/7"]);
    let xff = "2001:db8::1";
    assert_eq!(key_ip(peer("[fc00::1]:443"), &headers_with_xff(xff), &proxies), "2001:db8::1");
}

#[test]
fn combined_no_trusted_uses_peer() {
    let key = extract_rate_limit_key(
        LimitBy::Combined,
        peer("1.2.3.4:1234"),
        "/api",
        None,
        &headers_with_xff("9.9.9.9"),
        &[],
    );
    assert_eq!(key, "1.2.3.4:/api");
}

#[test]
fn combined_trusted_returns_real_client() {
    let proxies = nets(&["10.0.0.0/8"]);
    let key = extract_rate_limit_key(
        LimitBy::Combined,
        peer("10.0.0.1:443"),
        "/api",
        None,
        &headers_with_xff("203.0.113.5"),
        &proxies,
    );
    assert_eq!(key, "203.0.113.5:/api");
}

#[test]
fn header_strategy_unchanged() {
    let mut h = http::HeaderMap::new();
    h.insert(
        http::header::HeaderName::from_static("x-api-key"),
        http::header::HeaderValue::from_static("secret-token"),
    );
    let key = extract_rate_limit_key(
        LimitBy::Header,
        peer("1.2.3.4:1234"),
        "/",
        Some("x-api-key"),
        &h,
        &[],
    );
    assert_eq!(key, "secret-token");
}

#[test]
fn route_strategy_unchanged() {
    let key = extract_rate_limit_key(
        LimitBy::Route,
        peer("1.2.3.4:1234"),
        "/api",
        None,
        &headers_with_xff("9.9.9.9"),
        &[],
    );
    assert_eq!(key, "/api");
}
