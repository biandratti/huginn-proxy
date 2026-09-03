use std::io::{Error as IoError, ErrorKind};

use tokio_rustls::rustls::{Error as RustlsError, InvalidMessage};

use crate::telemetry::metrics::values;

/// Why a TLS accept failed, resolved once and used for both the log level and the
/// `error_type` metric label so the two can never disagree.
///
/// Unmatched SNI is decided by the accept path (`ServerCryptoMap::select` returned
/// `None`), not by parsing rustls `Error::General`. `tokio-rustls` maps a
/// mid-handshake TCP close to `ErrorKind::UnexpectedEof`. Non-TLS bytes become
/// `InvalidMessage::InvalidContentType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsAcceptFailure {
    /// Peer went away mid-handshake.
    PeerEof,
    /// No domain matched the ClientHello SNI.
    UnmatchedSni,
    /// Non-TLS bytes on the TLS port.
    NotTls,
    /// Certificate, mTLS or protocol failure: a real proxy-side problem.
    Other,
}

impl TlsAcceptFailure {
    /// Classify a `tokio-rustls` accept error. `unmatched_sni` wins over the transport
    /// error because a rejected SNI is the cause of whatever alert or close follows.
    pub fn classify(err: &IoError, unmatched_sni: bool) -> Self {
        if unmatched_sni {
            return Self::UnmatchedSni;
        }
        if err.kind() == ErrorKind::UnexpectedEof {
            return Self::PeerEof;
        }
        match rustls_error(err) {
            Some(RustlsError::InvalidMessage(InvalidMessage::InvalidContentType)) => Self::NotTls,
            _ => Self::Other,
        }
    }

    /// Routine client/scanner behavior rather than a proxy or certificate bug.
    pub fn is_expected(self) -> bool {
        !matches!(self, Self::Other)
    }

    /// Value for the `error_type` label on `huginn_tls_handshake_errors_total`.
    pub fn error_type(self) -> &'static str {
        match self {
            Self::PeerEof => values::TLS_ERROR_PEER_EOF,
            Self::UnmatchedSni => values::TLS_ERROR_UNMATCHED_SNI,
            Self::NotTls => values::TLS_ERROR_NOT_TLS,
            Self::Other => values::TLS_ERROR_OTHER,
        }
    }
}

fn rustls_error(err: &IoError) -> Option<&RustlsError> {
    err.get_ref()?.downcast_ref()
}
