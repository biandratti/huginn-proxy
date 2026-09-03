use huginn_proxy_lib::telemetry::values;
use huginn_proxy_lib::tls::TlsAcceptFailure;
use tokio_rustls::rustls::{Error as RustlsError, InvalidMessage};

fn wrap(tls: RustlsError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, tls)
}

#[test]
fn handshake_eof_is_expected() {
    let err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof");
    let failure = TlsAcceptFailure::classify(&err, false);
    assert_eq!(failure, TlsAcceptFailure::PeerEof);
    assert!(failure.is_expected());
    assert_eq!(failure.error_type(), values::TLS_ERROR_PEER_EOF);
}

#[test]
fn unmatched_sni_is_expected_regardless_of_rustls_error() {
    let err = wrap(RustlsError::AlertReceived(
        tokio_rustls::rustls::AlertDescription::UnrecognisedName,
    ));
    let failure = TlsAcceptFailure::classify(&err, true);
    assert_eq!(failure, TlsAcceptFailure::UnmatchedSni);
    assert!(failure.is_expected());
    assert_eq!(failure.error_type(), values::TLS_ERROR_UNMATCHED_SNI);
}

#[test]
fn invalid_content_type_is_expected() {
    let err = wrap(RustlsError::InvalidMessage(InvalidMessage::InvalidContentType));
    let failure = TlsAcceptFailure::classify(&err, false);
    assert_eq!(failure, TlsAcceptFailure::NotTls);
    assert!(failure.is_expected());
    assert_eq!(failure.error_type(), values::TLS_ERROR_NOT_TLS);
}

#[test]
fn mtls_missing_client_cert_stays_unexpected() {
    let err = wrap(RustlsError::NoCertificatesPresented);
    let failure = TlsAcceptFailure::classify(&err, false);
    assert_eq!(failure, TlsAcceptFailure::Other);
    assert!(!failure.is_expected());
    assert_eq!(failure.error_type(), values::TLS_ERROR_OTHER);
}

#[test]
fn expected_failures_have_distinct_error_types() {
    let types = [
        TlsAcceptFailure::PeerEof.error_type(),
        TlsAcceptFailure::UnmatchedSni.error_type(),
        TlsAcceptFailure::NotTls.error_type(),
        TlsAcceptFailure::Other.error_type(),
    ];
    let mut unique = types.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), types.len());
}
