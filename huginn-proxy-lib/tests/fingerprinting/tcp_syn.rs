use huginn_proxy_lib::fingerprinting::tcp_syn::{parse_syn_raw, TcpSynData};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn make_test_options() -> ([u8; 40], u16) {
    // Common Linux SYN options: MSS(1460), NOP, WS(6), NOP, NOP, TS, SOK
    // Meaningful bytes: 4+1+3+2+10+2 = 22 bytes; remaining 18 bytes are padding zeros.
    #[rustfmt::skip]
    let opts: [u8; 40] = [
        2, 4, 0x05, 0xb4,             // MSS = 1460
        1,                            // NOP
        3, 3, 6,                      // WS = 6
        1, 1,                         // NOP NOP
        8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // Timestamps
        4, 2,                         // SACK permitted
        0, 0, 0, 0, 0, 0, 0, 0,      // padding (18 bytes)
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    (opts, 22u16)
}

#[test]
fn test_parse_syn_raw_produces_signature() -> TestResult {
    let (options, optlen) = make_test_options();
    let data = TcpSynData { window: 65535u16.to_be(), ip_ttl: 64, optlen, options };
    let sig = parse_syn_raw(&data)
        .ok_or("parse_syn_raw returned None for valid input")?
        .to_string();
    assert!(!sig.is_empty());
    assert!(sig.starts_with("4:"));
    Ok(())
}

#[test]
fn test_signature_format_fields() -> TestResult {
    let (options, optlen) = make_test_options();
    let data = TcpSynData { window: 65535u16.to_be(), ip_ttl: 64, optlen, options };
    let sig = parse_syn_raw(&data)
        .ok_or("parse_syn_raw returned None")?
        .to_string();
    // Full p0f format: ver:ittl:olen:mss:wsize,wscale:olayout:quirks:pclass (8 fields)
    let parts: Vec<&str> = sig.split(':').collect();
    assert_eq!(parts.len(), 8, "signature must have 8 colon-separated fields: {sig}");
    assert_eq!(parts[0], "4", "ver field must be 4 (IPv4)");
    assert_eq!(parts[2], "0", "olen field must be 0 (IP options not available via eBPF)");
    assert!(
        parts[3].parse::<u16>().is_ok() || parts[3] == "*",
        "mss field must be a number or *"
    );
    assert!(!parts[5].is_empty(), "olayout field must not be empty");
    assert_eq!(parts[7], "0", "pclass must be 0 (SYN has no payload)");
    Ok(())
}

#[test]
fn test_empty_options_returns_some() {
    let data = TcpSynData { window: 8192u16.to_be(), ip_ttl: 128, optlen: 0, options: [0u8; 40] };
    assert!(parse_syn_raw(&data).is_some());
}

#[test]
fn test_ttl_field_is_numeric() -> TestResult {
    let (options, optlen) = make_test_options();
    let data = TcpSynData { window: 65535u16.to_be(), ip_ttl: 64, optlen, options };
    let sig = parse_syn_raw(&data)
        .ok_or("parse_syn_raw returned None")?
        .to_string();
    let ttl_field = sig
        .split(':')
        .nth(1)
        .ok_or("signature missing ittl field")?;
    assert!(
        ttl_field.parse::<u16>().is_ok(),
        "ittl field must be a number, got: {ttl_field}"
    );
    Ok(())
}

#[test]
fn test_window_byte_order_converted() -> TestResult {
    let (options, optlen) = make_test_options();
    // 8192 in network byte order
    let data = TcpSynData { window: 8192u16.to_be(), ip_ttl: 64, optlen, options };
    let sig = parse_syn_raw(&data)
        .ok_or("parse_syn_raw returned None")?
        .to_string();
    // wsize,wscale is at index 4; byte-swapped 8192 (0x2000) would be 32 (0x0020)
    let wsize_part = sig
        .split(':')
        .nth(4)
        .ok_or("signature missing wsize field")?;
    assert!(
        !wsize_part.contains("32"),
        "window must not appear byte-swapped, got: {wsize_part}"
    );
    Ok(())
}
