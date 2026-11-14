use std::net::{IpAddr, Ipv4Addr};

use http::header::{FORWARDED, HeaderName, HeaderValue};
use huginn_proxy_lib::config::TrustedProxiesConfig;
use huginn_proxy_lib::fingerprinting::forwarded;
use huginn_proxy_lib::proxy::handler::set_forwarded_for;

const XFF: HeaderName = HeaderName::from_static(forwarded::FOR);
/// The peer, inside the trusted range used by [`trusted`].
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

fn trusted() -> TrustedProxiesConfig {
    TrustedProxiesConfig {
        cidrs: ["10.0.0.0/8", "fc00::/7"]
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        insecure: false,
    }
}

fn untrusted() -> TrustedProxiesConfig {
    TrustedProxiesConfig::default()
}

fn headers_with_xff_fields(fields: &[&[u8]]) -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    for field in fields {
        if let Ok(hv) = HeaderValue::from_bytes(field) {
            h.append(XFF, hv);
        }
    }
    h
}

/// All `X-Forwarded-For` field lines after the call, as strings.
fn xff_fields(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get_all(XFF)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect()
}

/// `X-Forwarded-For` produced for `fields` arriving from the trusted [`PEER`].
fn from_trusted_peer(fields: &[&[u8]]) -> Vec<String> {
    let mut headers = headers_with_xff_fields(fields);
    set_forwarded_for(&mut headers, PEER, &trusted());
    xff_fields(&headers)
}

// --- untrusted peer -------------------------------------------------------------------

#[test]
fn untrusted_peer_without_header_gets_peer_only() {
    let mut headers = http::HeaderMap::new();
    set_forwarded_for(&mut headers, PEER, &untrusted());
    assert_eq!(xff_fields(&headers), ["10.0.0.1"]);
}

#[test]
fn untrusted_peer_chain_is_discarded() {
    // Whatever a direct client sends is client-supplied: only the peer is forwarded.
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5, 198.51.100.7", b"192.0.2.9"]);
    set_forwarded_for(&mut headers, PEER, &untrusted());
    assert_eq!(xff_fields(&headers), ["10.0.0.1"]);
}

#[test]
fn peer_outside_trusted_cidrs_is_untrusted() {
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5"]);
    let peer: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
    set_forwarded_for(&mut headers, peer, &trusted());
    assert_eq!(xff_fields(&headers), ["198.51.100.200"]);
}

#[test]
fn untrusted_peer_forwarded_header_is_removed() {
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5"]);
    headers.insert(FORWARDED, HeaderValue::from_static("for=203.0.113.5;proto=https"));
    set_forwarded_for(&mut headers, PEER, &untrusted());
    assert!(!headers.contains_key(FORWARDED));
}

// --- trusted peer ---------------------------------------------------------------------

#[test]
fn trusted_peer_without_header_gets_peer_only() {
    assert_eq!(from_trusted_peer(&[]), ["10.0.0.1"]);
}

#[test]
fn trusted_peer_client_hop_is_kept() {
    assert_eq!(from_trusted_peer(&[b"198.51.100.7"]), ["198.51.100.7, 10.0.0.1"]);
}

#[test]
fn trusted_peer_chain_is_cut_at_trust_boundary() {
    // 198.51.100.7 is the first non-trusted hop from the right: the real client. The entry
    // left of it was supplied by that client and is dropped.
    assert_eq!(
        from_trusted_peer(&[b"203.0.113.5, 198.51.100.7, 10.0.0.2"]),
        ["198.51.100.7, 10.0.0.2, 10.0.0.1"]
    );
}

#[test]
fn trusted_peer_repeated_fields_are_one_list() {
    // Same hops as the single-field case, sent as three field lines.
    assert_eq!(
        from_trusted_peer(&[b"203.0.113.5", b"198.51.100.7", b"10.0.0.2"]),
        ["198.51.100.7, 10.0.0.2, 10.0.0.1"]
    );
}

#[test]
fn trusted_peer_all_hops_trusted_keeps_whole_chain() {
    assert_eq!(from_trusted_peer(&[b"10.0.0.3, 10.0.0.2"]), ["10.0.0.3, 10.0.0.2, 10.0.0.1"]);
}

#[test]
fn trusted_peer_hops_are_canonicalized() {
    // Ports are dropped and IPv4-mapped IPv6 is folded, so the mapped hop is recognised
    // as the trusted proxy 10.0.0.2.
    assert_eq!(
        from_trusted_peer(&[b"198.51.100.7:51234, ::ffff:10.0.0.2"]),
        ["198.51.100.7, 10.0.0.2, 10.0.0.1"]
    );
    assert_eq!(from_trusted_peer(&[b"[2001:db8::1]:443"]), ["2001:db8::1, 10.0.0.1"]);
}

#[test]
fn trusted_peer_empty_members_are_ignored() {
    assert_eq!(from_trusted_peer(&[b"", b"198.51.100.7, ,", b"  "]), ["198.51.100.7, 10.0.0.1"]);
}

#[test]
fn trusted_peer_unparseable_hop_fails_closed() {
    // A hop that is not an IP anywhere in the chain discards it: only the peer is sent.
    for fields in [
        &[b"198.51.100.7, unknown".as_slice()][..],
        &[b"garbage, 198.51.100.7"],
        &[b"198.51.100.7", b"_hidden"],
    ] {
        assert_eq!(from_trusted_peer(fields), ["10.0.0.1"], "{fields:?}");
    }
}

#[test]
fn trusted_peer_unreadable_field_fails_closed() {
    assert_eq!(from_trusted_peer(&[b"203.0.113.5", b"\xff\xfe", b"198.51.100.7"]), ["10.0.0.1"]);
}

#[test]
fn trusted_peer_forwarded_header_is_passed_through() {
    let mut headers = headers_with_xff_fields(&[b"198.51.100.7"]);
    headers.insert(FORWARDED, HeaderValue::from_static("for=198.51.100.7"));
    set_forwarded_for(&mut headers, PEER, &trusted());
    assert_eq!(headers.get(FORWARDED).and_then(|v| v.to_str().ok()), Some("for=198.51.100.7"));
}

#[test]
fn insecure_trusts_every_hop() {
    // `insecure = true` trusts all peers and all hops, so nothing is cut.
    let all = TrustedProxiesConfig { cidrs: Vec::new(), insecure: true };
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5, 198.51.100.7"]);
    set_forwarded_for(&mut headers, PEER, &all);
    assert_eq!(xff_fields(&headers), ["203.0.113.5, 198.51.100.7, 10.0.0.1"]);
}
