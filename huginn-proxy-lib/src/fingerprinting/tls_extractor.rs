use tokio::time::Instant;

use super::ja4::Ja4Fingerprints;
use crate::telemetry::Metrics;

/// Max bytes buffered while waiting for a complete ClientHello.
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// Largest record `tls-parser` accepts (2^14 + 256).
const MAX_RECORD_LEN: usize = (1 << 14) + 256;

#[derive(Debug, PartialEq, Eq)]
pub enum ClientHelloScan {
    /// Message incomplete; read more.
    NeedMore,
    /// Not a parsable handshake; parse buffer as is.
    AsIs,
    /// Whole ClientHello as one record, joined if it was fragmented.
    Complete(Vec<u8>),
}

/// Find first handshake message in `buf`, joining it if split across records (RFC 8446 §5.1).
pub fn scan_client_hello(buf: &[u8]) -> ClientHelloScan {
    let mut payload = Vec::new();
    let mut offset = 0;
    loop {
        match buf.get(offset) {
            None => return ClientHelloScan::NeedMore,
            Some(&CONTENT_TYPE_HANDSHAKE) => {}
            Some(_) => return ClientHelloScan::AsIs,
        }
        let Some(header) = buf.get(offset..offset + RECORD_HEADER_LEN) else {
            return ClientHelloScan::NeedMore;
        };
        let start = offset + RECORD_HEADER_LEN;
        offset = start + u16::from_be_bytes([header[3], header[4]]) as usize;
        let Some(fragment) = buf.get(start..offset) else {
            return ClientHelloScan::NeedMore;
        };
        payload.extend_from_slice(fragment);

        let Some(&[_, a, b, c]) = payload.get(..HANDSHAKE_HEADER_LEN) else {
            continue;
        };
        let msg_len = HANDSHAKE_HEADER_LEN + u32::from_be_bytes([0, a, b, c]) as usize;
        if msg_len > MAX_RECORD_LEN {
            return ClientHelloScan::AsIs;
        }
        if payload.len() >= msg_len {
            payload.truncate(msg_len);
            // msg_len <= MAX_RECORD_LEN, fits in u16.
            let mut record = vec![CONTENT_TYPE_HANDSHAKE, buf[1], buf[2]];
            record.extend_from_slice(&(msg_len as u16).to_be_bytes());
            record.extend_from_slice(&payload);
            return ClientHelloScan::Complete(record);
        }
    }
}

/// Reads TLS ClientHello from the stream and extracts JA4 fingerprint.
/// Returns all bytes read so caller can replay them into the TLS acceptor.
pub async fn read_client_hello(
    stream: &mut tokio::net::TcpStream,
    metrics: &Metrics,
) -> std::io::Result<(Vec<u8>, Option<Ja4Fingerprints>)> {
    use huginn_net_tls::tls_process::parse_tls_client_hello;
    use tokio::io::AsyncReadExt;

    let start = Instant::now();
    let mut buf = Vec::with_capacity(8192);
    let client_hello = loop {
        match scan_client_hello(&buf) {
            ClientHelloScan::NeedMore => {}
            ClientHelloScan::AsIs => break None,
            ClientHelloScan::Complete(record) => break Some(record),
        }
        let read = stream.read_buf(&mut buf).await?;
        if read == 0 {
            break None;
        }
        if buf.len() > MAX_CLIENT_HELLO_BYTES {
            break None;
        }
    };

    let duration = start.elapsed().as_secs_f64();

    let fingerprints = match parse_tls_client_hello(client_hello.as_deref().unwrap_or(&buf)) {
        Ok(signature) => {
            metrics.tls_fingerprints_extracted_total.add(1, &[]);
            metrics
                .tls_fingerprint_extraction_duration_seconds
                .record(duration, &[]);
            let ja4 = signature.generate_ja4();
            let ja4_original = signature.generate_ja4_original();
            let ja4_stable_v1 = signature.generate_ja4_stable_v1();
            let sni = signature.sni;
            Some(Ja4Fingerprints::new(ja4, ja4_original, ja4_stable_v1, sni))
        }
        Err(_) => {
            metrics.tls_fingerprint_failures_total.add(1, &[]);
            None
        }
    };

    Ok((buf, fingerprints))
}
