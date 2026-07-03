use huginn_proxy_lib::proxy::protocol::{read_proxy_header_v1, ProxyProtocolError, ProxySource};
use std::io::Cursor;
use tokio::io::AsyncReadExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn v1_parses_tcp4() -> TestResult {
    let mut cursor = Cursor::new(b"PROXY TCP4 192.168.1.100 10.0.0.1 45000 443\r\n".to_vec());
    let src = read_proxy_header_v1(&mut cursor).await?;
    assert_eq!(src, ProxySource::Client("192.168.1.100:45000".parse()?));
    Ok(())
}

#[tokio::test]
async fn v1_parses_tcp6() -> TestResult {
    let mut cursor = Cursor::new(b"PROXY TCP6 2001:db8::1 2001:db8::2 45000 443\r\n".to_vec());
    let src = read_proxy_header_v1(&mut cursor).await?;
    assert_eq!(src, ProxySource::Client("[2001:db8::1]:45000".parse()?));
    Ok(())
}

#[tokio::test]
async fn v1_unknown_maps_to_local() -> TestResult {
    let mut cursor = Cursor::new(b"PROXY UNKNOWN\r\n".to_vec());
    assert_eq!(read_proxy_header_v1(&mut cursor).await?, ProxySource::Local);
    Ok(())
}

#[tokio::test]
async fn v1_consumes_exactly_leaving_clienthello() -> TestResult {
    // Byte-by-byte read must stop at the CRLF, leaving the ClientHello untouched.
    let client_hello = [0x16u8, 0x03, 0x01, 0x00, 0x2a, 0xde, 0xad];
    let mut stream = b"PROXY TCP4 203.0.113.5 10.0.0.1 12345 443\r\n".to_vec();
    stream.extend_from_slice(&client_hello);

    let mut cursor = Cursor::new(stream);
    let src = read_proxy_header_v1(&mut cursor).await?;
    assert_eq!(src, ProxySource::Client("203.0.113.5:12345".parse()?));

    let mut rest = Vec::new();
    cursor.read_to_end(&mut rest).await?;
    assert_eq!(rest, client_hello, "ClientHello bytes must remain after the v1 header");
    Ok(())
}

#[tokio::test]
async fn v1_malformed_is_rejected() {
    let mut cursor = Cursor::new(b"PROXY TCP4 not_an_ip 10.0.0.1 45000 443\r\n".to_vec());
    let result = read_proxy_header_v1(&mut cursor).await;
    assert!(matches!(result, Err(ProxyProtocolError::Parse(_))), "got {result:?}");
}

#[tokio::test]
async fn v1_overlong_without_crlf_is_rejected() {
    // 120 bytes of 'A' with no CRLF exceeds the 107-byte v1 cap.
    let mut cursor = Cursor::new(vec![b'A'; 120]);
    let result = read_proxy_header_v1(&mut cursor).await;
    assert!(matches!(result, Err(ProxyProtocolError::V1HeaderTooLong)), "got {result:?}");
}
