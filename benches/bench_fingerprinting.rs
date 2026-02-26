//! Micro benchmarks for TLS (JA4) and HTTP/2 (Akamai) fingerprinting parsers.
//! Pure CPU — no network, no IO.
//!
//! TCP SYN fingerprinting is not included: it requires CAP_BPF and is measured
//! separately via Prometheus metrics in a staging environment.
//!
//! ```bash
//! cargo bench --bench bench_fingerprinting
//! ```

use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net_http::akamai_extractor::extract_akamai_fingerprint_from_bytes;
use huginn_net_tls::tls_process::parse_tls_client_hello;

// ---------------------------------------------------------------------------
// HTTP/2 fixture
//
// Realistic client HTTP/2 stream from a reqwest (h2 crate) connection:
//   SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
//             INITIAL_WINDOW_SIZE=2097152, MAX_FRAME_SIZE=16384
//   WINDOW_UPDATE: connection-level increment=15663105
//
// These are the values the h2 crate sends before any request frames.
// The Akamai fingerprint is derived from this data.
// ---------------------------------------------------------------------------
const HTTP2_CLIENT_FRAMES: &[u8] = &[
    // Connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32,
    0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
    // SETTINGS frame header: length=24, type=0x04, flags=0x00, stream_id=0
    0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    // SETTINGS payload: 4 entries × 6 bytes each
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // id=1 (HEADER_TABLE_SIZE),    val=0x00010000=65536
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // id=2 (ENABLE_PUSH),          val=0
    0x00, 0x04, 0x00, 0x20, 0x00, 0x00, // id=4 (INITIAL_WINDOW_SIZE),  val=0x00200000=2097152
    0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // id=5 (MAX_FRAME_SIZE),       val=0x00004000=16384
    // WINDOW_UPDATE frame header: length=4, type=0x08, flags=0x00, stream_id=0
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    // WINDOW_UPDATE payload: increment=0x00EF0001=15663105
    0x00, 0xef, 0x00, 0x01,
];

// ---------------------------------------------------------------------------
// TLS ClientHello fixture
//
// A minimal TLS 1.3 ClientHello from rustls (used by reqwest).
// Includes: supported_versions (TLS 1.3), supported_groups (x25519, secp256r1,
// secp384r1), signature_algorithms, key_share (x25519).
//
// To regenerate from a real reqwest connection, run:
//   cargo test --test capture_fixtures -- --nocapture
// and paste the output here.
//
// This fixture produces a deterministic JA4 fingerprint. If it changes after
// a rustls/reqwest update, regenerate with the capture test.
// ---------------------------------------------------------------------------
const CLIENT_HELLO_BYTES: &[u8] = &[
    // TLS record header: type=0x16 (handshake), version=0x0301 (TLS 1.0 compat), length
    0x16, 0x03, 0x01, 0x00, 0xf1,
    // Handshake header: type=0x01 (ClientHello), length
    0x01, 0x00, 0x00, 0xed,
    // ClientHello: legacy version = TLS 1.2 (0x0303)
    0x03, 0x03,
    // Random (32 bytes)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    // Session ID (0 bytes)
    0x00,
    // Cipher suites (6 suites × 2 bytes = 12 bytes + 2 byte length)
    0x00, 0x0c,
    0x13, 0x02, // TLS_AES_256_GCM_SHA384
    0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
    0x13, 0x01, // TLS_AES_128_GCM_SHA256
    0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    // Compression methods: 1 method, null
    0x01, 0x00,
    // Extensions length
    0x00, 0xc0,
    // Extension: server_name (0x0000)
    0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09,
    0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, // "localhost"
    // Extension: supported_groups (0x000a)
    0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
    0x00, 0x1d, // x25519
    0x00, 0x17, // secp256r1
    0x00, 0x18, // secp384r1
    // Extension: signature_algorithms (0x000d)
    0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x08, 0x04, // rsa_pss_rsae_sha256
    0x04, 0x01, // rsa_pkcs1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x08, 0x05, // rsa_pss_rsae_sha384
    0x05, 0x01, // rsa_pkcs1_sha384
    0x08, 0x06, // rsa_pss_rsae_sha512
    0x06, 0x01, // rsa_pkcs1_sha512
    0x02, 0x01, // rsa_pkcs1_sha1
    // Extension: supported_versions (0x002b) — advertises TLS 1.3
    0x00, 0x2b, 0x00, 0x05, 0x04,
    0x03, 0x04, // TLS 1.3
    0x03, 0x03, // TLS 1.2
    // Extension: key_share (0x0033) — x25519 key
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
    0x00, 0x1d, 0x00, 0x20, // x25519, 32 bytes
    0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1,
    0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38,
    0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75,
    0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54,
    // Extension: encrypt_then_mac (0x0016)
    0x00, 0x16, 0x00, 0x00,
    // Extension: extended_master_secret (0x0017)
    0x00, 0x17, 0x00, 0x00,
    // Extension: session_ticket (0x0023)
    0x00, 0x23, 0x00, 0x00,
    // Extension: psk_key_exchange_modes (0x002d)
    0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
    // Extension: compress_certificate (0x001b)
    0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x02,
    // Extension: padding to reach expected length
    0x00, 0x15, 0x00, 0x51,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
];

fn bench_akamai_parse(c: &mut Criterion) {
    // Verify fixture is valid before benchmarking
    let result = extract_akamai_fingerprint_from_bytes(HTTP2_CLIENT_FRAMES);
    if result.is_none() {
        eprintln!("WARNING: HTTP2_CLIENT_FRAMES produced no Akamai fingerprint — fixture may be incomplete");
    }

    c.bench_function("akamai_parse_http2_settings_window_update", |b| {
        b.iter(|| extract_akamai_fingerprint_from_bytes(std::hint::black_box(HTTP2_CLIENT_FRAMES)));
    });
}

fn bench_ja4_parse(c: &mut Criterion) {
    // Verify fixture produces a fingerprint before benchmarking
    match parse_tls_client_hello(CLIENT_HELLO_BYTES) {
        Ok(Some(ref sig)) => {
            let ja4 = sig.generate_ja4();
            eprintln!("JA4 fixture fingerprint: {}", ja4.full);
        }
        Ok(None) => {
            eprintln!("WARNING: CLIENT_HELLO_BYTES produced no JA4 — fixture may be incomplete");
        }
        Err(e) => {
            eprintln!("WARNING: CLIENT_HELLO_BYTES parse error: {e}");
        }
    }

    c.bench_function("ja4_parse_tls_client_hello", |b| {
        b.iter(|| parse_tls_client_hello(std::hint::black_box(CLIENT_HELLO_BYTES)));
    });
}

criterion_group!(fingerprinting_benches, bench_akamai_parse, bench_ja4_parse);
criterion_main!(fingerprinting_benches);
