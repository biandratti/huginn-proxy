use huginn_net_tls::tls_process::parse_tls_client_hello;
use huginn_proxy_lib::Metrics;
use huginn_proxy_lib::fingerprinting::read_client_hello;
use huginn_proxy_lib::fingerprinting::tls_extractor::{ClientHelloScan, scan_client_hello};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Single-record ClientHello from reqwest/rustls.
const CLIENT_HELLO: &[u8] = include_bytes!("../../../benches/fixtures/clienthello_reqwest.bin");

/// Split `CLIENT_HELLO` payload into records of at most `chunk` bytes.
fn fragmented_client_hello(chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for part in CLIENT_HELLO[5..].chunks(chunk) {
        out.extend_from_slice(&CLIENT_HELLO[..3]);
        out.extend_from_slice(&u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[test]
fn scan_client_hello_cases() {
    let complete = ClientHelloScan::Complete(CLIENT_HELLO.to_vec());
    let fragmented = fragmented_client_hello(64);
    assert!(parse_tls_client_hello(&fragmented).is_err());
    assert!(parse_tls_client_hello(CLIENT_HELLO).is_ok());

    let cases: [(&str, &[u8], ClientHelloScan); 8] = [
        ("single record", CLIENT_HELLO, complete.clone()),
        ("fragmented", &fragmented, complete.clone()),
        ("1-byte records", &fragmented_client_hello(1), complete.clone()),
        ("3-byte records", &fragmented_client_hello(3), complete.clone()),
        ("partial header", &CLIENT_HELLO[..3], ClientHelloScan::NeedMore),
        ("partial record", &CLIENT_HELLO[..100], ClientHelloScan::NeedMore),
        (
            "missing last fragment byte",
            &fragmented[..fragmented.len() - 1],
            ClientHelloScan::NeedMore,
        ),
        ("not TLS", b"GET / HTTP/1.1\r\n", ClientHelloScan::AsIs),
    ];
    for (name, input, expected) in cases {
        assert_eq!(scan_client_hello(input), expected, "{name}");
    }
}

#[tokio::test]
async fn read_client_hello_fingerprints_fragmented_client_hello()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let fragmented = fragmented_client_hello(64);

    let client = tokio::spawn({
        let fragmented = fragmented.clone();
        async move {
            let mut stream = TcpStream::connect(addr).await?;
            for part in fragmented.chunks(37) {
                stream.write_all(part).await?;
                stream.flush().await?;
                tokio::task::yield_now().await;
            }
            Ok::<_, std::io::Error>(stream)
        }
    });

    let (mut stream, _) = listener.accept().await?;
    let (prefix, fingerprints) = read_client_hello(&mut stream, &Metrics::new_noop()).await?;
    let _client = client.await??;

    assert_eq!(prefix, fragmented);
    assert!(fingerprints.is_some());
    Ok(())
}
