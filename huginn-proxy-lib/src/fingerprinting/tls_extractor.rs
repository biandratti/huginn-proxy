use huginn_net_tls::Ja4Payload;
use std::sync::Arc;
use tokio::time::Instant;

use crate::telemetry::Metrics;

/// Reads TLS ClientHello from the stream and extracts JA4 fingerprint
pub async fn read_client_hello(
    stream: &mut tokio::net::TcpStream,
    metrics: Option<Arc<Metrics>>,
) -> std::io::Result<(Vec<u8>, Option<Ja4Payload>)> {
    use huginn_net_tls::tls_process::parse_tls_client_hello;
    use tokio::io::AsyncReadExt;

    let start = Instant::now();
    let mut buf = Vec::with_capacity(8192);
    loop {
        if buf.len() >= 5 {
            let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let needed = len.saturating_add(5);
            if buf.len() >= needed {
                break;
            }
        }
        let read = stream.read_buf(&mut buf).await?;
        if read == 0 {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }

    let ja4 = parse_tls_client_hello(&buf)
        .ok()
        .and_then(|opt_signature| opt_signature.map(|signature| signature.generate_ja4()));

    let duration = start.elapsed().as_secs_f64();

    if let Some(ref m) = metrics {
        if ja4.is_some() {
            m.tls_fingerprints_extracted_total.add(1, &[]);
            m.tls_fingerprint_extraction_duration_seconds
                .record(duration, &[]);
        } else {
            // Failed to extract TLS fingerprint
            m.tls_fingerprint_failures_total.add(1, &[]);
        }
    }

    Ok((buf, ja4))
}
