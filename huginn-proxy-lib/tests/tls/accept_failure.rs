use huginn_proxy_lib::telemetry::values;
use huginn_proxy_lib::tls::{FailureSeverity, TlsAcceptFailure};
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

/// Connect-then-reset is what most scanners and some load-balancer health checks do, and
/// it reaches us as a raw socket error while reading the ClientHello, before rustls sees
/// anything. It has to be classified as peer noise or it keeps the log at `warn`.
#[test]
fn peer_reset_is_expected() {
    for kind in [
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::BrokenPipe,
    ] {
        let err = std::io::Error::new(kind, "peer went away");
        let failure = TlsAcceptFailure::classify(&err, false);
        assert_eq!(failure, TlsAcceptFailure::PeerEof, "{kind:?}");
        assert!(failure.is_expected(), "{kind:?}");
        assert_eq!(failure.error_type(), values::TLS_ERROR_PEER_EOF, "{kind:?}");
    }
}

/// A read fault that is not the peer disconnecting is a real proxy-side problem.
#[test]
fn other_io_errors_stay_unexpected() {
    let err = std::io::Error::new(std::io::ErrorKind::OutOfMemory, "no buffers");
    let failure = TlsAcceptFailure::classify(&err, false);
    assert_eq!(failure, TlsAcceptFailure::Other);
    assert!(!failure.is_expected());
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

/// An unmatched SNI is usually a domain missing from the config, so unlike the rest of
/// the routine noise it stays visible at the default log level. Same call as rpxy makes.
#[test]
fn unmatched_sni_stays_visible_at_info() {
    let err = wrap(RustlsError::AlertReceived(
        tokio_rustls::rustls::AlertDescription::UnrecognisedName,
    ));
    let failure = TlsAcceptFailure::classify(&err, true);
    assert_eq!(failure.severity(), FailureSeverity::Info);
}

/// Peer noise must not reach the default log level, and a real fault must.
#[test]
fn severity_splits_noise_from_faults() {
    let cases = [
        (TlsAcceptFailure::PeerEof, FailureSeverity::Debug),
        (TlsAcceptFailure::NotTls, FailureSeverity::Debug),
        (TlsAcceptFailure::UnmatchedSni, FailureSeverity::Info),
        (TlsAcceptFailure::Other, FailureSeverity::Warn),
    ];
    for (failure, expected) in cases {
        assert_eq!(failure.severity(), expected, "{failure:?}");
        assert_eq!(
            failure.is_expected(),
            expected != FailureSeverity::Warn,
            "is_expected must track severity for {failure:?}"
        );
    }
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
