use huginn_ebpf::types::{parse_syn_v4, parse_syn_v6, quirk_bits, SynRawDataV4, SynRawDataV6};
use huginn_net_tcp::tcp::{IpVersion, PayloadSize, Quirk};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn make_test_options() -> ([u8; 40], u8) {
    // Common Linux SYN options: MSS(1460), NOP, WS(6), NOP, NOP, TS, SOK
    // Meaningful bytes: 4+1+3+2+10+2 = 22 bytes; remaining 18 bytes are padding zeros.
    #[rustfmt::skip]
    let opts: [u8; 40] = [
        2, 4, 0x05, 0xb4,               // MSS = 1460
        1,                              // NOP
        3, 3, 6,                        // WS = 6
        1, 1,                           // NOP NOP
        8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // Timestamps
        4, 2,                           // SACK permitted
        0, 0, 0, 0, 0, 0, 0, 0,        // padding (18 bytes)
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    (opts, 22u8)
}

fn make_syn_raw(window: u16, ip_ttl: u8, optlen: u8, options: [u8; 40]) -> SynRawDataV4 {
    make_syn_raw_with_quirks(window, ip_ttl, optlen, options, 0)
}

fn make_syn_raw_with_quirks(
    window: u16,
    ip_ttl: u8,
    optlen: u8,
    options: [u8; 40],
    quirks: u32,
) -> SynRawDataV4 {
    make_syn_raw_full(window, ip_ttl, 0, 0, optlen, options, quirks)
}

fn make_syn_raw_full(
    window: u16,
    ip_ttl: u8,
    ip_tos: u8,
    ip_olen: u8,
    optlen: u8,
    options: [u8; 40],
    quirks: u32,
) -> SynRawDataV4 {
    SynRawDataV4 {
        src_addr: 0,
        src_port: 0,
        window,
        optlen,
        ip_tos,
        ip_ttl,
        ip_olen,
        options,
        quirks,
        tick: 0,
    }
}

fn make_syn_raw_v6(
    window: u16,
    ip_ttl: u8,
    ip_tos: u8,
    optlen: u8,
    options: [u8; 40],
    quirks: u32,
) -> SynRawDataV6 {
    SynRawDataV6 {
        src_addr: [0u8; 16],
        src_port: 0,
        window,
        optlen,
        ip_tos,
        ip_ttl,
        _pad: 0,
        options,
        quirks,
        tick: 0,
    }
}

#[test]
fn test_parse_syn_produces_signature() -> TestResult {
    let (options, optlen) = make_test_options();
    let raw = make_syn_raw(65535u16.to_be(), 64, optlen, options);
    let sig = parse_syn_v4(&raw)
        .ok_or("parse_syn_v4 returned None for valid input")?
        .to_string();
    assert!(!sig.is_empty());
    assert!(sig.starts_with("4:"));
    Ok(())
}

#[test]
fn test_signature_format_fields() -> TestResult {
    let (options, optlen) = make_test_options();
    let raw = make_syn_raw(65535u16.to_be(), 64, optlen, options);
    let sig = parse_syn_v4(&raw)
        .ok_or("parse_syn_v4 returned None")?
        .to_string();
    // Full p0f format: ver:ittl:olen:mss:wsize,wscale:olayout:quirks:pclass (8 fields)
    let parts: Vec<&str> = sig.split(':').collect();
    assert_eq!(parts.len(), 8, "signature must have 8 colon-separated fields: {sig}");
    assert_eq!(parts[0], "4", "ver field must be 4 (IPv4)");
    assert_eq!(parts[2], "0", "olen field must be 0 (no IP options)");
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
    let raw = make_syn_raw(8192u16.to_be(), 128, 0, [0u8; 40]);
    assert!(parse_syn_v4(&raw).is_some());
}

#[test]
fn test_ttl_field_is_valid() -> TestResult {
    let (options, optlen) = make_test_options();
    let raw = make_syn_raw(65535u16.to_be(), 64, optlen, options);
    let sig = parse_syn_v4(&raw)
        .ok_or("parse_syn_v4 returned None")?
        .to_string();
    let ttl_field = sig
        .split(':')
        .nth(1)
        .ok_or("signature missing ittl field")?;
    // Valid p0f TTL formats: "64" (Value), "64+2" (Distance), "64+?" (Guess), "64-" (Bad)
    let base = ttl_field
        .split(['+', '-'])
        .next()
        .ok_or("ittl field is empty")?;
    assert!(base.parse::<u8>().is_ok(), "ittl base must be a number, got: {ttl_field}");
    Ok(())
}

#[test]
fn test_window_byte_order_converted() -> TestResult {
    let (options, optlen) = make_test_options();
    // 8192 in network byte order; byte-swapped value would be 32 (0x0020)
    let raw = make_syn_raw(8192u16.to_be(), 64, optlen, options);
    let sig = parse_syn_v4(&raw)
        .ok_or("parse_syn_v4 returned None")?
        .to_string();
    // wsize,wscale is at index 4
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

/// Each quirk bit in the XDP-captured bitmask must decode to the corresponding Quirk in TcpObservation.
/// Protects decode_quirks() and quirk_bits parity with the XDP side.
#[test]
fn test_all_quirk_bits_roundtrip() -> TestResult {
    let (options, optlen) = make_test_options();
    let cases: &[(u32, Quirk)] = &[
        (quirk_bits::DF, Quirk::Df),
        (quirk_bits::NONZERO_ID, Quirk::NonZeroID),
        (quirk_bits::ZERO_ID, Quirk::ZeroID),
        (quirk_bits::MUST_BE_ZERO, Quirk::MustBeZero),
        (quirk_bits::ECN, Quirk::Ecn),
        (quirk_bits::SEQ_ZERO, Quirk::SeqNumZero),
        (quirk_bits::ACK_NONZERO, Quirk::AckNumNonZero),
        (quirk_bits::NONZERO_URG, Quirk::NonZeroURG),
        (quirk_bits::URG, Quirk::Urg),
        (quirk_bits::PUSH, Quirk::Push),
        (quirk_bits::FLOW, Quirk::FlowID),
    ];
    for (bit, expected_quirk) in cases {
        let raw = make_syn_raw_with_quirks(65535u16.to_be(), 64, optlen, options, *bit);
        let obs = parse_syn_v4(&raw).ok_or("parse_syn_v4 returned None for valid options")?;
        assert!(
            obs.quirks.contains(*expected_quirk),
            "quirk bit 0x{:x} should decode to {:?}, got quirks: {:?}",
            bit,
            expected_quirk,
            obs.quirks
        );
    }
    Ok(())
}

#[test]
fn test_raw_wsize_and_tot_hdr() -> TestResult {
    let (options, optlen) = make_test_options();
    let ip_olen = 0u8;
    let raw = make_syn_raw_full(8192u16.to_be(), 64, 0, ip_olen, optlen, options, 0);
    let obs = parse_syn_v4(&raw).ok_or("parse_syn_v4 returned None")?;

    assert_eq!(obs.wsize, 8192, "wsize must be host-endian raw window");
    assert_eq!(
        obs.tot_hdr,
        20u16
            .saturating_add(u16::from(ip_olen))
            .saturating_add(20)
            .saturating_add(u16::from(optlen)),
        "tot_hdr must include IP header + TCP header with options"
    );
    assert_eq!(obs.peer_mss, None, "SYN observations have no peer_mss");

    let wsize_part = obs
        .to_string()
        .split(':')
        .nth(4)
        .ok_or("signature missing wsize field")?
        .to_string();
    // 8192 / 1460 is not exact; Display should keep the raw value or an mss*/mtu* form
    // that does not look like a byte-swapped window.
    assert!(
        wsize_part.starts_with("8192,")
            || wsize_part.contains("mss*")
            || wsize_part.contains("mtu*"),
        "unexpected wsize display field: {wsize_part}"
    );
    Ok(())
}

#[test]
fn test_tos_is_dscp() -> TestResult {
    let (options, optlen) = make_test_options();
    // ToS 0xB8 → DSCP 0x2E (EF)
    let raw = make_syn_raw_full(8192u16.to_be(), 64, 0xB8, 0, optlen, options, 0);
    let obs = parse_syn_v4(&raw).ok_or("parse_syn_v4 returned None")?;
    assert_eq!(obs.tos, 0x2E, "tos must be DSCP (ip_tos >> 2)");
    Ok(())
}

#[test]
fn test_parse_syn_v6_fields() -> TestResult {
    let (options, optlen) = make_test_options();
    // traffic class 0xB8 → DSCP 0x2E
    let raw = make_syn_raw_v6(8192u16.to_be(), 64, 0xB8, optlen, options, quirk_bits::FLOW);
    let obs = parse_syn_v6(&raw).ok_or("parse_syn_v6 returned None")?;

    assert_eq!(obs.version, IpVersion::V6);
    assert_eq!(obs.olen, 0, "IPv6 fixed-header path has no extension olen");
    assert_eq!(
        obs.tot_hdr,
        40u16.saturating_add(20).saturating_add(u16::from(optlen)),
        "tot_hdr must be IPv6 header + TCP header with options"
    );
    assert_eq!(obs.wsize, 8192);
    assert_eq!(obs.tos, 0x2E);
    assert_eq!(obs.peer_mss, None);
    assert!(obs.quirks.contains(Quirk::FlowID));
    assert!(!obs.quirks.contains(Quirk::Df), "IPv4-only quirks must not appear");

    let sig = obs.to_string();
    assert!(sig.starts_with("6:"), "signature must start with IPv6 version: {sig}");
    assert!(sig.contains("flow"), "Display must include p0f flow quirk: {sig}");
    Ok(())
}

/// PAYLOAD_NONZERO rides in the quirks bitmask but must decode to pclass, not a quirk.
#[test]
fn test_payload_nonzero_bit_sets_pclass() -> TestResult {
    let (options, optlen) = make_test_options();

    let bare = make_syn_raw_with_quirks(65535u16.to_be(), 64, optlen, options, 0);
    let sig = parse_syn_v4(&bare)
        .ok_or("parse_syn_v4 returned None")?
        .to_string();
    assert!(sig.ends_with(":0"), "SYN without data must have pclass 0: {sig}");

    let with_data = make_syn_raw_with_quirks(
        65535u16.to_be(),
        64,
        optlen,
        options,
        quirk_bits::PAYLOAD_NONZERO,
    );
    let obs = parse_syn_v4(&with_data).ok_or("parse_syn_v4 returned None")?;
    assert_eq!(obs.pclass, PayloadSize::NonZero, "TFO SYN must have pclass +");
    let sig = obs.to_string();
    assert!(sig.ends_with(":+"), "TFO SYN must render pclass +: {sig}");

    let v6 = make_syn_raw_v6(65535u16.to_be(), 64, 0, optlen, options, quirk_bits::PAYLOAD_NONZERO);
    let obs = parse_syn_v6(&v6).ok_or("parse_syn_v6 returned None")?;
    assert_eq!(obs.pclass, PayloadSize::NonZero);
    assert!(
        obs.quirks.is_empty(),
        "PAYLOAD_NONZERO must not decode as a quirk, got: {:?}",
        obs.quirks
    );
    Ok(())
}

#[test]
fn test_parse_syn_v6_empty_options() {
    let raw = make_syn_raw_v6(8192u16.to_be(), 128, 0, 0, [0u8; 40], 0);
    let Some(obs) = parse_syn_v6(&raw) else {
        panic!("parse_syn_v6 returned None for empty options");
    };
    assert_eq!(obs.tot_hdr, 60);
    assert_eq!(obs.olen, 0);
}
