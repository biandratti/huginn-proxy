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

fn complete() -> ClientHelloScan {
    ClientHelloScan::Complete(CLIENT_HELLO.to_vec())
}

#[test]
fn single_record_client_hello_is_complete() {
    assert_eq!(scan_client_hello(CLIENT_HELLO), complete());
}

#[test]
fn partial_record_needs_more_bytes() {
    assert_eq!(scan_client_hello(&CLIENT_HELLO[..3]), ClientHelloScan::NeedMore);
    assert_eq!(scan_client_hello(&CLIENT_HELLO[..100]), ClientHelloScan::NeedMore);
}

/// Regression: huginn-net-tls parses only the first record, so fragmented ClientHello failed.
#[test]
fn fragmented_client_hello_is_reassembled() {
    let fragmented = fragmented_client_hello(64);
    assert!(parse_tls_client_hello(&fragmented).is_err());
    assert_eq!(scan_client_hello(&fragmented), complete());
    assert!(parse_tls_client_hello(CLIENT_HELLO).is_ok());
}

/// Records smaller than the 4-byte handshake header.
#[test]
fn tiny_records_are_reassembled() {
    for chunk in [1, 3, 5] {
        assert_eq!(scan_client_hello(&fragmented_client_hello(chunk)), complete(), "chunk {chunk}");
    }
}

#[test]
fn fragmented_client_hello_needs_all_fragments() {
    let fragmented = fragmented_client_hello(64);
    assert_eq!(
        scan_client_hello(&fragmented[..fragmented.len() - 1]),
        ClientHelloScan::NeedMore
    );
}

#[test]
fn non_handshake_record_is_parsed_as_is() {
    assert_eq!(scan_client_hello(b"GET / HTTP/1.1\r\n"), ClientHelloScan::AsIs);
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
