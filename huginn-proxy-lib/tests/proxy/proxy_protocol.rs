use huginn_proxy_lib::proxy::proxy_protocol::{
    normalize_mapped_ipv4, read_proxy_header_v2, ProxyProtocolError, V2_SIGNATURE,
};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::AsyncReadExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Wire-format values from the PROXY protocol v2 spec (§2.2).
const CMD_LOCAL: u8 = 0x0;
const CMD_PROXY: u8 = 0x1;
const FAM_INET: u8 = 0x1;
const FAM_INET6: u8 = 0x2;
const FIXED_LEN: usize = 16;

/// Build a v2 header: signature + ver/cmd + fam/proto + len + address block.
fn build_header(cmd: u8, fam: u8, addrs: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&V2_SIGNATURE);
    buf.push((2 << 4) | (cmd & 0x0F));
    buf.push((fam << 4) | 0x1); // protocol = STREAM (0x1)
    buf.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
    buf.extend_from_slice(addrs);
    buf
}

fn v4_block(src: [u8; 4], src_port: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&src); // src
    b.extend_from_slice(&[10, 0, 0, 1]); // dst (ignored)
    b.extend_from_slice(&src_port.to_be_bytes()); // src port
    b.extend_from_slice(&8443u16.to_be_bytes()); // dst port (ignored)
    b
}

fn v6_block(src: [u8; 16], src_port: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&src); // src
    b.extend_from_slice(&[0u8; 16]); // dst (ignored)
    b.extend_from_slice(&src_port.to_be_bytes()); // src port
    b.extend_from_slice(&8443u16.to_be_bytes()); // dst port (ignored)
    b
}

#[tokio::test]
async fn parses_valid_ipv4() -> TestResult {
    let header = build_header(CMD_PROXY, FAM_INET, &v4_block([192, 168, 1, 100], 51234));
    let mut cursor = Cursor::new(header);
    let src = read_proxy_header_v2(&mut cursor).await?;
    assert_eq!(src, Some("192.168.1.100:51234".parse()?));
    Ok(())
}

#[tokio::test]
async fn parses_valid_ipv6() -> TestResult {
    let octets = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
    let header = build_header(CMD_PROXY, FAM_INET6, &v6_block(octets, 40000));
    let mut cursor = Cursor::new(header);
    let src = read_proxy_header_v2(&mut cursor).await?;
    assert_eq!(src, Some("[2001:db8::1]:40000".parse()?));
    Ok(())
}

#[tokio::test]
async fn local_command_returns_none() -> TestResult {
    // LOCAL command (health checks): no address block.
    let header = build_header(CMD_LOCAL, 0x0, &[]);
    let mut cursor = Cursor::new(header);
    let src = read_proxy_header_v2(&mut cursor).await?;
    assert_eq!(src, None);
    Ok(())
}

#[tokio::test]
async fn af_unspec_falls_back() -> TestResult {
    // PROXY command but AF_UNSPEC family → no usable source.
    let header = build_header(CMD_PROXY, 0x0, &[]);
    let mut cursor = Cursor::new(header);
    let src = read_proxy_header_v2(&mut cursor).await?;
    assert_eq!(src, None);
    Ok(())
}

#[tokio::test]
async fn bad_signature_is_rejected() {
    let mut bytes = vec![0u8; FIXED_LEN];
    bytes[0] = 0xFF; // corrupt the signature
    let mut cursor = Cursor::new(bytes);
    let result = read_proxy_header_v2(&mut cursor).await;
    assert!(matches!(result, Err(ProxyProtocolError::BadSignature)), "got {result:?}");
}

#[tokio::test]
async fn v1_text_header_is_unsupported_version() {
    // A v1 text header ("PROXY TCP4 ...") does not match the binary signature.
    let mut cursor = Cursor::new(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".to_vec());
    let result = read_proxy_header_v2(&mut cursor).await;
    assert!(matches!(result, Err(ProxyProtocolError::BadSignature)), "got {result:?}");
}

#[tokio::test]
async fn truncated_address_block_errors() {
    // Announce AF_INET but provide fewer than 12 address bytes.
    let header = build_header(CMD_PROXY, FAM_INET, &[1, 2, 3, 4]);
    let mut cursor = Cursor::new(header);
    let result = read_proxy_header_v2(&mut cursor).await;
    assert!(matches!(result, Err(ProxyProtocolError::Truncated)), "got {result:?}");
}

#[tokio::test]
async fn consumes_exactly_header_leaving_clienthello() -> TestResult {
    // Header followed by a synthetic TLS ClientHello prefix. After parsing, the next bytes
    // read must equal the ClientHello untouched (alignment proof).
    let client_hello = [0x16u8, 0x03, 0x01, 0x00, 0x2a, 0xde, 0xad, 0xbe, 0xef];
    let mut stream = build_header(CMD_PROXY, FAM_INET, &v4_block([203, 0, 113, 5], 12345));
    stream.extend_from_slice(&client_hello);

    let mut cursor = Cursor::new(stream);
    let src = read_proxy_header_v2(&mut cursor).await?;
    assert_eq!(src, Some("203.0.113.5:12345".parse()?));

    let mut rest = Vec::new();
    cursor.read_to_end(&mut rest).await?;
    assert_eq!(rest, client_hello, "ClientHello bytes must remain after the header");
    Ok(())
}

#[tokio::test]
async fn oversized_addr_len_is_rejected() {
    // addr_len far beyond any real address block must be rejected before allocation.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&V2_SIGNATURE);
    bytes.push((2 << 4) | CMD_PROXY);
    bytes.push((FAM_INET << 4) | 0x1);
    bytes.extend_from_slice(&(4096u16).to_be_bytes()); // > V2_MAX_ADDR_LEN (2048)
    let mut cursor = Cursor::new(bytes);
    let result = read_proxy_header_v2(&mut cursor).await;
    assert!(
        matches!(result, Err(ProxyProtocolError::AddrLenTooLarge(4096))),
        "got {result:?}"
    );
}

#[test]
fn normalizes_ipv4_mapped_ipv6() {
    let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
    assert_eq!(normalize_mapped_ipv4(mapped), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    // A plain IPv4 and a genuine IPv6 are returned unchanged.
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(normalize_mapped_ipv4(v4), v4);
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert_eq!(normalize_mapped_ipv4(v6), v6);
}

#[tokio::test]
async fn ignores_trailing_tlvs_but_consumes_them() -> TestResult {
    // Address block longer than the minimum (TLVs appended) must be fully consumed.
    let mut block = v4_block([10, 1, 2, 3], 5555);
    block.extend_from_slice(&[0x03, 0x00, 0x02, 0xAA, 0xBB]); // a fake TLV
    let client_hello = [0x16u8, 0x03, 0x03];
    let mut stream = build_header(CMD_PROXY, FAM_INET, &block);
    stream.extend_from_slice(&client_hello);

    let mut cursor = Cursor::new(stream);
    let src = read_proxy_header_v2(&mut cursor).await?;
    assert_eq!(src, Some("10.1.2.3:5555".parse()?));

    let mut rest = Vec::new();
    cursor.read_to_end(&mut rest).await?;
    assert_eq!(rest, client_hello);
    Ok(())
}
