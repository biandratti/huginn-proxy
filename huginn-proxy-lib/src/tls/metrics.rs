use opentelemetry::KeyValue;
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

        m.tls_handshakes_total.add(
            1,
            &[
                KeyValue::new("tls_version", tls_version.clone()),
                KeyValue::new("cipher_suite", cipher_suite.clone()),
            ],
        );
        m.tls_handshake_duration_seconds.record(
            handshake_duration,
            &[
                KeyValue::new("tls_version", tls_version),
                KeyValue::new("cipher_suite", cipher_suite),
            ],
        );
        m.tls_connections_active.add(1, &[]);
    }
}
