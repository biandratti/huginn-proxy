use std::sync::Arc;

use crate::telemetry::Metrics;

pub fn extract_tls_info<S>(tls: &tokio_rustls::server::TlsStream<S>) -> (String, String) {
    let (_, connection) = tls.get_ref();

    let tls_version = connection
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".to_string());

    let cipher_suite = connection
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "unknown".to_string());

    (tls_version, cipher_suite)
}

pub fn record_tls_handshake_metrics<S>(
    tls: &tokio_rustls::server::TlsStream<S>,
    handshake_duration: f64,
    metrics: Option<Arc<Metrics>>,
) {
    if let Some(ref m) = metrics {
        let (tls_version, cipher_suite) = extract_tls_info(tls);
        let (_, connection) = tls.get_ref();

        m.record_tls_handshake(&tls_version, &cipher_suite, handshake_duration);
        m.record_tls_connection_active();

        if connection.peer_certificates().is_some() {
            let protocol = connection
                .protocol_version()
                .map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "unknown".to_string());
            m.record_mtls_connection(&protocol);
        }
    }
}
