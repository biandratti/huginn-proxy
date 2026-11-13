use std::net::{IpAddr, Ipv4Addr};

use http::header::{HeaderName, HeaderValue};
use huginn_proxy_lib::proxy::handler::append_forwarded_for;

const XFF: HeaderName = HeaderName::from_static("x-forwarded-for");
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

fn headers_with_xff_fields(fields: &[&[u8]]) -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    for field in fields {
        if let Ok(hv) = HeaderValue::from_bytes(field) {
            h.append(XFF, hv);
        }
    }
    h
}

/// All `X-Forwarded-For` field lines after the append, as strings.
fn xff_fields(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get_all(XFF)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect()
}

#[test]
fn creates_header_when_missing() {
    let mut headers = http::HeaderMap::new();
    append_forwarded_for(&mut headers, PEER);
    assert_eq!(xff_fields(&headers), ["10.0.0.1"]);
}

#[test]
fn appends_to_single_field() {
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5, 198.51.100.7"]);
    append_forwarded_for(&mut headers, PEER);
    assert_eq!(xff_fields(&headers), ["203.0.113.5, 198.51.100.7, 10.0.0.1"]);
}

#[test]
fn repeated_fields_are_joined_in_order() {
    // Same hops as the single-field case, sent as two field lines: no hop is dropped.
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5", b"198.51.100.7"]);
    append_forwarded_for(&mut headers, PEER);
    assert_eq!(xff_fields(&headers), ["203.0.113.5, 198.51.100.7, 10.0.0.1"]);
}

#[test]
fn repeated_fields_with_lists_are_joined_in_order() {
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5, 10.0.0.2", b"10.0.0.3"]);
    append_forwarded_for(&mut headers, PEER);
    assert_eq!(xff_fields(&headers), ["203.0.113.5, 10.0.0.2, 10.0.0.3, 10.0.0.1"]);
}

#[test]
fn empty_fields_are_ignored() {
    let mut headers = headers_with_xff_fields(&[b"", b"198.51.100.7", b"  "]);
    append_forwarded_for(&mut headers, PEER);
    assert_eq!(xff_fields(&headers), ["198.51.100.7, 10.0.0.1"]);
}

#[test]
fn unreadable_field_discards_inbound_chain() {
    // Fail closed: a non-ASCII field means a hop would go missing, so only the peer is sent.
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5", b"\xff\xfe", b"198.51.100.7"]);
    append_forwarded_for(&mut headers, PEER);
    assert_eq!(xff_fields(&headers), ["10.0.0.1"]);
}

#[test]
fn ipv6_peer_is_appended() {
    let mut headers = headers_with_xff_fields(&[b"203.0.113.5"]);
    let peer: IpAddr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    append_forwarded_for(&mut headers, peer);
    assert_eq!(xff_fields(&headers), ["203.0.113.5, ::1"]);
}
