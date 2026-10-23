use huginn_net_tls::tls_process::parse_tls_client_hello;
use huginn_proxy_lib::Metrics;
use huginn_proxy_lib::fingerprinting::read_client_hello;
use huginn_proxy_lib::fingerprinting::tls_extractor::{ClientHelloScan, ClientHelloScanner};
use tokio::io::AsyncWriteExt;

/// Single-record ClientHello from reqwest/rustls.
const CLIENT_HELLO: &[u8] = include_bytes!("../../../benches/fixtures/clienthello_reqwest.bin");

fn client_hello_records(chunk: usize) -> Vec<Vec<u8>> {
    CLIENT_HELLO[5..]
        .chunks(chunk)
        .map(|part| {
            let len = u16::try_from(part.len())
                .unwrap_or_else(|_| panic!("chunk of {} bytes exceeds a record", part.len()));
            let mut record = CLIENT_HELLO[..3].to_vec();
            record.extend_from_slice(&len.to_be_bytes());
            record.extend_from_slice(part);
            record
        })
        .collect()
}

fn scan(buf: &[u8]) -> ClientHelloScan {
    ClientHelloScanner::default().scan(buf)
}

#[test]
fn scan_client_hello_cases() {
    let complete = ClientHelloScan::Complete(CLIENT_HELLO.to_vec());
    let fragmented = client_hello_records(64).concat();
    // Regression: huginn-net-tls parses only the first record.
    assert!(parse_tls_client_hello(&fragmented).is_err());
    assert!(parse_tls_client_hello(CLIENT_HELLO).is_ok());

    let cases: [(&str, &[u8], ClientHelloScan); 8] = [
        ("single record", CLIENT_HELLO, complete.clone()),
        ("fragmented", &fragmented, complete.clone()),
        ("1-byte records", &client_hello_records(1).concat(), complete.clone()),
        ("3-byte records", &client_hello_records(3).concat(), complete.clone()),
        ("partial header", &CLIENT_HELLO[..3], ClientHelloScan::NeedMore),
        ("partial record", &CLIENT_HELLO[..100], ClientHelloScan::NeedMore),
        (
            "missing last fragment byte",
            &fragmented[..fragmented.len().saturating_sub(1)],
            ClientHelloScan::NeedMore,
        ),
        ("not TLS", b"GET / HTTP/1.1\r\n", ClientHelloScan::AsIs),
    ];
    for (name, input, expected) in cases {
        assert_eq!(scan(input), expected, "{name}");
    }

    // Same scanner fed one byte at a time keeps its place between calls.
    let tiny = client_hello_records(1).concat();
    let mut scanner = ClientHelloScanner::default();
    for end in 0..tiny.len() {
        assert_eq!(scanner.scan(&tiny[..end]), ClientHelloScan::NeedMore, "{end} bytes");
    }
    assert_eq!(scanner.scan(&tiny), complete);
}

#[tokio::test]
async fn read_client_hello_fingerprints_fragmented_client_hello()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fragmented = client_hello_records(64).concat();
    // 6-byte pipe: every read returns at most 6 bytes, forcing many reads.
    let (mut client, mut server) = tokio::io::duplex(6);
    let writer = tokio::spawn({
        let fragmented = fragmented.clone();
        async move { client.write_all(&fragmented).await }
    });

    let (prefix, fingerprints) = read_client_hello(&mut server, &Metrics::new_noop()).await?;
    writer.await??;

    assert_eq!(prefix, fragmented);
    assert!(fingerprints.is_some());
    Ok(())
}
