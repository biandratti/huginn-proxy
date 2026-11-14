use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use huginn_proxy_lib::proxy::handler::{strip_hop_by_hop, strip_request_hop_by_hop};

fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (name, value) in pairs {
        h.append(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    h
}

fn names(nominated: &[HeaderName]) -> Vec<&str> {
    nominated.iter().map(HeaderName::as_str).collect()
}

#[test]
fn fixed_hop_by_hop_headers_are_removed() {
    let mut h = headers(&[
        ("connection", "keep-alive"),
        ("keep-alive", "timeout=5"),
        ("proxy-connection", "keep-alive"),
        ("proxy-authenticate", "Basic"),
        ("proxy-authorization", "Basic Zm9vOmJhcg=="),
        ("te", "gzip"),
        ("trailer", "x-checksum"),
        ("transfer-encoding", "chunked"),
        ("upgrade", "websocket"),
        ("content-type", "text/plain"),
        ("authorization", "Bearer token"),
    ]);
    strip_hop_by_hop(&mut h);
    let mut left: Vec<&str> = h.keys().map(HeaderName::as_str).collect();
    left.sort_unstable();
    assert_eq!(left, ["authorization", "content-type"]);
}

#[test]
fn headers_nominated_by_connection_are_removed() {
    let mut h = headers(&[
        ("connection", "X-Tls-Ja4 ,  , x-custom"),
        ("x-tls-ja4", "forged"),
        ("x-custom", "v"),
        ("x-other", "kept"),
    ]);
    let nominated = strip_hop_by_hop(&mut h);
    assert_eq!(names(&nominated), ["x-tls-ja4", "x-custom"]);
    assert!(!h.contains_key("x-tls-ja4"));
    assert!(!h.contains_key("x-custom"));
    assert!(!h.contains_key(header::CONNECTION));
    assert!(h.contains_key("x-other"));
}

#[test]
fn repeated_connection_lines_are_one_list() {
    // The second field line must not be ignored.
    let mut h =
        headers(&[("connection", "close"), ("connection", "x-tls-ja4"), ("x-tls-ja4", "forged")]);
    let nominated = strip_hop_by_hop(&mut h);
    assert_eq!(names(&nominated), ["close", "x-tls-ja4"]);
    assert!(h.is_empty());
}

#[test]
fn invalid_connection_members_are_ignored() {
    let mut h = headers(&[("connection", "x custom, x-ok"), ("x-ok", "v")]);
    let nominated = strip_hop_by_hop(&mut h);
    assert_eq!(names(&nominated), ["x-ok"]);
    assert!(h.is_empty());
}

#[test]
fn without_connection_nothing_is_nominated() {
    let mut h = headers(&[("x-custom", "v")]);
    assert!(strip_hop_by_hop(&mut h).is_empty());
    assert!(h.contains_key("x-custom"));
}

#[test]
fn request_keeps_te_trailers_only() {
    for te in ["trailers", "Trailers", "gzip, trailers", "trailers;q=0.5, deflate"] {
        let mut h = headers(&[("connection", "te"), ("te", te)]);
        strip_request_hop_by_hop(&mut h);
        assert_eq!(h.get(header::TE).and_then(|v| v.to_str().ok()), Some("trailers"), "{te}");
        assert!(!h.contains_key(header::CONNECTION));
    }
}

#[test]
fn request_drops_te_without_trailers() {
    let mut h = headers(&[("te", "gzip, deflate")]);
    strip_request_hop_by_hop(&mut h);
    assert!(!h.contains_key(header::TE));
}

#[test]
fn response_does_not_keep_te() {
    let mut h = headers(&[("te", "trailers")]);
    strip_hop_by_hop(&mut h);
    assert!(!h.contains_key(header::TE));
}
