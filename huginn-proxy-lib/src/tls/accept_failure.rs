use std::io::{Error as IoError, ErrorKind};

use tokio_rustls::rustls::{Error as RustlsError, InvalidMessage};

/// Peer/scanner TLS failures that are not a proxy or certificate bug.
///
/// Unmatched SNI is decided by the accept path (`ServerCryptoMap::select` returned
/// `None`), not by parsing rustls `Error::General`. `tokio-rustls` maps a
/// mid-handshake TCP close to `ErrorKind::UnexpectedEof`. Non-TLS bytes become
/// `InvalidMessage::InvalidContentType`.
pub fn is_expected_tls_accept_failure(err: &IoError, unmatched_sni: bool) -> bool {
    if unmatched_sni || err.kind() == ErrorKind::UnexpectedEof {
        return true;
    }
    matches!(
        rustls_error(err),
        Some(RustlsError::InvalidMessage(InvalidMessage::InvalidContentType))
    )
}

fn rustls_error(err: &IoError) -> Option<&RustlsError> {
    err.get_ref()?.downcast_ref()
}
