//! Hop-by-hop header removal (RFC 9110 §7.6.1).

use http::header::{self, HeaderMap, HeaderName, HeaderValue};

static HOP_BY_HOP: [HeaderName; 9] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

fn list_members<'a>(headers: &'a HeaderMap, name: &HeaderName) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|member| !member.is_empty())
}

/// Removes hop-by-hop headers and returns the names `Connection` nominated.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) -> Vec<HeaderName> {
    let nominated: Vec<HeaderName> = list_members(headers, &header::CONNECTION)
        .filter_map(|member| HeaderName::from_bytes(member.as_bytes()).ok())
        .collect();
    for name in &nominated {
        headers.remove(name);
    }
    for name in &HOP_BY_HOP {
        headers.remove(name);
    }
    nominated
}

/// [`strip_hop_by_hop`] for upstream requests; keeps `TE: trailers` (gRPC needs it).
pub fn strip_request_hop_by_hop(headers: &mut HeaderMap) -> Vec<HeaderName> {
    let te_trailers = list_members(headers, &header::TE).any(|member| {
        member
            .split(';')
            .next()
            .is_some_and(|coding| coding.trim().eq_ignore_ascii_case("trailers"))
    });
    let nominated = strip_hop_by_hop(headers);
    if te_trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
    }
    nominated
}
