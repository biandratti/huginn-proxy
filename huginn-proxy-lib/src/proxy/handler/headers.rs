use huginn_net_http::AkamaiFingerprint;
use hyper::header::HeaderValue;

/// Convert Akamai fingerprint to HTTP header value
pub fn akamai_header_value(value: &Option<AkamaiFingerprint>) -> Option<HeaderValue> {
    value
        .as_ref()
        .and_then(|f| HeaderValue::from_str(&f.fingerprint).ok())
}

/// Convert TLS (JA4) fingerprint to HTTP header value
pub fn tls_header_value(value: &Option<huginn_net_tls::Ja4Payload>) -> Option<HeaderValue> {
    value
        .as_ref()
        .and_then(|f| HeaderValue::from_str(&f.full.to_string()).ok())
}
