use huginn_proxy_lib::tls::is_expected_tls_accept_failure;
use tokio_rustls::rustls::{Error as RustlsError, InvalidMessage};

fn wrap(tls: RustlsError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, tls)
}

#[test]
fn handshake_eof_is_expected() {
    let err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof");
    assert!(is_expected_tls_accept_failure(&err, false));
}

#[test]
fn unmatched_sni_is_expected_regardless_of_rustls_error() {
    let err = wrap(RustlsError::AlertReceived(
        tokio_rustls::rustls::AlertDescription::UnrecognisedName,
    ));
    assert!(is_expected_tls_accept_failure(&err, true));
}

#[test]
fn invalid_content_type_is_expected() {
    let err = wrap(RustlsError::InvalidMessage(InvalidMessage::InvalidContentType));
    assert!(is_expected_tls_accept_failure(&err, false));
}

#[test]
fn mtls_missing_client_cert_stays_unexpected() {
    let err = wrap(RustlsError::NoCertificatesPresented);
    assert!(!is_expected_tls_accept_failure(&err, false));
}
