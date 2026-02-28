//! Micro benchmarks for TLS (JA4) and HTTP/2 (Akamai) fingerprinting parsers.
//! Pure CPU - no network, no IO.
//!
//! TCP SYN fingerprinting is not included: it requires CAP_BPF and is measured
//! separately via Prometheus metrics in a staging environment.
//!
//! ```bash
//! cargo bench --bench bench_fingerprinting
//! ```
//!
//! Fixtures are real bytes captured from a reqwest/rustls connection.
//! To refresh them after a reqwest or rustls update, run:
//! ```bash
//! cargo test -p huginn-proxy-lib --test capture_fixtures -- --nocapture
//! ```

use criterion::{criterion_group, criterion_main, Criterion};
use huginn_net_http::akamai_extractor::extract_akamai_fingerprint_from_bytes;
use huginn_net_tls::tls_process::parse_tls_client_hello;

// ---------------------------------------------------------------------------
// TLS ClientHello fixture - real bytes from reqwest/rustls
//
// Captured via `cargo test --test capture_fixtures -- --nocapture`.
// The file is committed so benchmarks are deterministic without needing
// an active network connection.
// ---------------------------------------------------------------------------
const CLIENT_HELLO_BYTES: &[u8] = include_bytes!("fixtures/clienthello_reqwest.bin");

// ---------------------------------------------------------------------------
// HTTP/2 client frames fixture - real values from reqwest/h2
//
// Derived from the Akamai fingerprint captured via capture_fixtures:
//   2:0;4:2097152;5:16384;6:16384|5177345|0|
// SETTINGS: ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=2097152,
//           MAX_FRAME_SIZE=16384, MAX_HEADER_LIST_SIZE=16384
// WINDOW_UPDATE: increment=5177345
//
// To capture raw bytes from the H2 stream, run capture_fixtures.
// ---------------------------------------------------------------------------
const HTTP2_CLIENT_FRAMES: &[u8] = &[
    // Connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
    0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
    // SETTINGS frame header: length=24, type=0x04, flags=0x00, stream_id=0
    0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    // SETTINGS payload: 4 entries × 6 bytes
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // id=2 (ENABLE_PUSH),          val=0
    0x00, 0x04, 0x00, 0x20, 0x00, 0x00, // id=4 (INITIAL_WINDOW_SIZE),  val=0x00200000=2097152
    0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // id=5 (MAX_FRAME_SIZE),       val=0x00004000=16384
    0x00, 0x06, 0x00, 0x00, 0x40, 0x00, // id=6 (MAX_HEADER_LIST_SIZE), val=0x00004000=16384
    // WINDOW_UPDATE frame header: length=4, type=0x08, flags=0x00, stream_id=0
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    // WINDOW_UPDATE payload: increment=0x004F0001=5177345
    0x00, 0x4f, 0x00, 0x01,
];

/// JA4 fingerprint produced by these CLIENT_HELLO_BYTES.
/// If this changes after a reqwest/rustls update, re-run capture_fixtures
/// and update this constant + the fixture file.
const EXPECTED_JA4: &str = "t13i1010h2_61a7ad8aa9b6_3a8073edd8ef";

/// Akamai fingerprint produced by these HTTP2_CLIENT_FRAMES.
const EXPECTED_AKAMAI: &str = "2:0;4:2097152;5:16384;6:16384|5177345|0|";

fn bench_akamai_parse(c: &mut Criterion) {
    let result = extract_akamai_fingerprint_from_bytes(HTTP2_CLIENT_FRAMES);
    match &result {
        Some(fp) => {
            assert_eq!(
                fp.fingerprint, EXPECTED_AKAMAI,
                "Akamai fixture mismatch - re-run capture_fixtures and update EXPECTED_AKAMAI"
            );
        }
        None => panic!("HTTP2_CLIENT_FRAMES produced no Akamai fingerprint - fixture is invalid"),
    }

    c.bench_function("akamai_parse_http2_settings_window_update", |b| {
        b.iter(|| extract_akamai_fingerprint_from_bytes(std::hint::black_box(HTTP2_CLIENT_FRAMES)));
    });
}

fn bench_ja4_parse(c: &mut Criterion) {
    match parse_tls_client_hello(CLIENT_HELLO_BYTES) {
        Ok(Some(ref sig)) => {
            let ja4 = sig.generate_ja4();
            assert_eq!(
                ja4.full.to_string(),
                EXPECTED_JA4,
                "JA4 fixture mismatch - re-run capture_fixtures and update EXPECTED_JA4"
            );
        }
        Ok(None) => panic!("CLIENT_HELLO_BYTES produced no JA4 - fixture is invalid"),
        Err(e) => panic!("CLIENT_HELLO_BYTES parse error: {e}"),
    }

    c.bench_function("ja4_parse_tls_client_hello", |b| {
        b.iter(|| parse_tls_client_hello(std::hint::black_box(CLIENT_HELLO_BYTES)));
    });
}

criterion_group!(fingerprinting_benches, bench_akamai_parse, bench_ja4_parse);
criterion_main!(fingerprinting_benches);
