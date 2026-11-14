use huginn_proxy_lib::config::{LimitBy, TrustedProxiesConfig};
use huginn_proxy_lib::fingerprinting::forwarded;
use huginn_proxy_lib::security::extract_rate_limit_key;

fn peer(s: &str) -> std::net::SocketAddr {
    s.parse()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
}

fn nets(cidrs: &[&str]) -> TrustedProxiesConfig {
    TrustedProxiesConfig {
        cidrs: cidrs.iter().filter_map(|s| s.parse().ok()).collect(),
        insecure: false,
    }
}

fn none() -> TrustedProxiesConfig {
    TrustedProxiesConfig::default()
}

fn headers_with_xff(xff: &str) -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    if let Ok(hv) = http::header::HeaderValue::from_str(xff) {
        h.insert(http::header::HeaderName::from_static(forwarded::FOR), hv);
    }
    h
}

fn headers_with_xff_fields(fields: &[&str]) -> http::HeaderMap {
    headers_with_xff_bytes(&fields.iter().map(|f| f.as_bytes()).collect::<Vec<_>>())
}

fn headers_with_xff_bytes(fields: &[&[u8]]) -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    for field in fields {
        if let Ok(hv) = http::header::HeaderValue::from_bytes(field) {
            h.append(http::header::HeaderName::from_static(forwarded::FOR), hv);
        }
    }
    h
}

fn key_ip(
    peer_addr: std::net::SocketAddr,
    headers: &http::HeaderMap,
    proxies: &TrustedProxiesConfig,
) -> String {
    extract_rate_limit_key(LimitBy::Ip, peer_addr, "/", None, headers, proxies)
}

#[test]
fn ip_no_trusted_uses_peer() {
    // No trusted_proxies → always peer IP, even with XFF present.
    assert_eq!(key_ip(peer("1.2.3.4:1234"), &headers_with_xff("9.9.9.9"), &none()), "1.2.3.4");
}

#[test]
fn ip_spoof_rotation_pinned_to_peer() {
    // Client rotates XFF values, result never changes without trusted_proxies.
    let proxies = none();
    let p = peer("1.2.3.4:1234");
    for xff in &["10.0.0.1", "172.16.0.1", "203.0.113.5, 10.0.0.1"] {
        assert_eq!(key_ip(p, &headers_with_xff(xff), &proxies), "1.2.3.4");
    }
}

#[test]
fn ip_insecure_trusts_all_falls_back_to_peer() {
    // `insecure = true` trusts every peer and every XFF hop, so (like an explicit 0.0.0.0/0
    // entry) resolution falls back to the TCP peer IP.
    let proxies = TrustedProxiesConfig { cidrs: vec![], insecure: true };
    assert_eq!(
        key_ip(peer("8.8.8.8:80"), &headers_with_xff("203.0.113.5"), &proxies),
        "8.8.8.8"
    );
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
    // An unparseable XFF entry fails closed to the peer IP.
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
fn ip_trusted_peer_joined_xff_returns_real_client() {
    // Two hops in one comma-joined X-Forwarded-For value, peer is trusted.
    let proxies = nets(&["10.0.0.0/8"]);
    let xff = "203.0.113.5, 198.51.100.7";
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies), "198.51.100.7");
}

#[test]
fn ip_trusted_peer_repeated_xff_fields_returns_real_client() {
    // Same two hops as the joined case, sent as two X-Forwarded-For field lines.
    // The last field is the hop the trusted peer appended.
    let proxies = nets(&["10.0.0.0/8"]);
    let headers = headers_with_xff_fields(&["203.0.113.5", "198.51.100.7"]);
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers, &proxies), "198.51.100.7");
}

#[test]
fn ip_trusted_peer_repeated_xff_fields_skips_trusted_hops() {
    // Trusted hops split across fields still walk back to the client address.
    let proxies = nets(&["10.0.0.0/8"]);
    let headers = headers_with_xff_fields(&["203.0.113.5, 10.0.0.2", "10.0.0.3"]);
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers, &proxies), "203.0.113.5");
}

#[test]
fn ip_unparseable_trusted_hop_fails_closed() {
    // The rightmost hop was written by the trusted peer. If it cannot be parsed, the walk
    // must not step left onto the client-controlled entry.
    let proxies = nets(&["10.0.0.0/8"]);
    for xff in [
        "1.2.3.4, unknown",
        "1.2.3.4, not-an-ip",
        "1.2.3.4, _hidden",
        "1.2.3.4, 198.51.100.7:x",
    ] {
        assert_eq!(
            key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies),
            "10.0.0.1",
            "{xff}"
        );
    }
}

#[test]
fn ip_unparseable_hop_behind_trusted_hops_fails_closed() {
    let proxies = nets(&["10.0.0.0/8"]);
    let headers = headers_with_xff_fields(&["1.2.3.4", "garbage", "10.0.0.2"]);
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers, &proxies), "10.0.0.1");
}

#[test]
fn ip_unreadable_field_fails_closed() {
    // A non-ASCII field line right of the client entry is not skipped.
    let proxies = nets(&["10.0.0.0/8"]);
    let headers = headers_with_xff_bytes(&[b"1.2.3.4", b"\xff\xfe"]);
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers, &proxies), "10.0.0.1");
}

#[test]
fn ip_garbage_left_of_client_hop_is_not_inspected() {
    // Entries left of the first non-trusted hop are client-supplied and irrelevant.
    let proxies = nets(&["10.0.0.0/8"]);
    let xff = "garbage, 198.51.100.7, 10.0.0.2";
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies), "198.51.100.7");
}

#[test]
fn ip_hop_with_port_is_accepted() {
    let proxies = nets(&["10.0.0.0/8", "fc00::/7"]);
    for (xff, want) in [
        ("1.2.3.4, 198.51.100.7:51234", "198.51.100.7"),
        ("1.2.3.4, [2001:db8::1]:443", "2001:db8::1"),
        ("1.2.3.4, [2001:db8::1]", "2001:db8::1"),
        ("1.2.3.4, 198.51.100.7, 10.0.0.2:8080, [fc00::2]:80", "198.51.100.7"),
    ] {
        assert_eq!(key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies), want, "{xff}");
    }
}

#[test]
fn ip_malformed_port_fails_closed() {
    let proxies = nets(&["10.0.0.0/8"]);
    for xff in [
        "1.2.3.4, 198.51.100.7:",
        "1.2.3.4, 198.51.100.7:99999",
        "1.2.3.4, 198.51.100.7:+80",
        "1.2.3.4, [2001:db8::1]x",
        "1.2.3.4, [2001:db8::1",
        "1.2.3.4, [198.51.100.7]",
    ] {
        assert_eq!(
            key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies),
            "10.0.0.1",
            "{xff}"
        );
    }
}

#[test]
fn ip_mapped_ipv4_hop_matches_ipv4_trusted_cidr() {
    // `::ffff:10.0.0.2` is the trusted proxy 10.0.0.2, not a client.
    let proxies = nets(&["10.0.0.0/8"]);
    let xff = "198.51.100.7, ::ffff:10.0.0.2";
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies), "198.51.100.7");
}

#[test]
fn ip_empty_list_members_are_ignored() {
    let proxies = nets(&["10.0.0.0/8"]);
    let xff = "198.51.100.7, , 10.0.0.2,";
    assert_eq!(key_ip(peer("10.0.0.1:443"), &headers_with_xff(xff), &proxies), "198.51.100.7");
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
        &none(),
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
        &none(),
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
        &none(),
    );
    assert_eq!(key, "/api");
}
