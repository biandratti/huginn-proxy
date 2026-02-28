//! Integration benchmarks for Huginn Proxy.
//!
//! Measures full round-trip latency and throughput through a real proxy instance
//! with TLS termination and fingerprinting enabled. No mocks: the proxy is started
//! as a library, the backend is an embedded Hyper server, clients use reqwest.
//!
//! ## What is real
//! - TLS handshake (rcgen self-signed cert, reqwest/rustls client)
//! - JA4 fingerprinting (extracted from the actual TLS ClientHello bytes)
//! - Akamai fingerprinting (extracted from real HTTP/2 frames via CapturingStream)
//! - TCP networking (localhost, OS network stack)
//! - Backend is a real Hyper HTTP/1.1 server
//!
//! ## What is simplified
//! - TCP SYN eBPF fingerprinting: disabled (requires CAP_BPF + kernel ≥ 5.11).
//!   Measured separately via Prometheus metrics in production.
//! - Backend always returns 200 OK: we benchmark the proxy, not the backend.
//!
//! ## Run
//! ```bash
//! cargo bench --bench bench_proxy
//! # Save a named baseline for regression comparison:
//! cargo bench --bench bench_proxy -- --save-baseline v0_1_0
//! # Compare against saved baseline:
//! cargo bench --bench bench_proxy -- --baseline v0_1_0
//! ```

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http_body_util::Full;
use huginn_proxy_lib::config::{
    Backend, FingerprintConfig, KeepAliveConfig, LoggingConfig, Route, SecurityConfig,
    TelemetryConfig, TimeoutConfig,
};
use huginn_proxy_lib::{Config, TlsConfig};
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Fingerprint header names (mirrors huginn_proxy_lib::fingerprinting::names)
// ---------------------------------------------------------------------------
const HEADER_JA4: &str = "x-huginn-net-ja4";
const HEADER_AKAMAI: &str = "x-huginn-net-akamai";

// ---------------------------------------------------------------------------
// Expected fingerprint values - captured from a real reqwest/rustls connection.
//
// If these change after a reqwest/rustls/h2 update, the benchmarks will panic
// with a clear message. Re-run the capture test to refresh:
//   cargo test -p huginn-proxy-lib --test capture_fixtures -- --nocapture
// Then update these constants with the new values.
// ---------------------------------------------------------------------------
const EXPECTED_JA4: &str = "t13i1010h2_61a7ad8aa9b6_3a8073edd8ef";
const EXPECTED_AKAMAI: &str = "2:0;4:2097152;5:16384;6:16384|5177345|0|";

// ---------------------------------------------------------------------------
// Fixture: holds live servers for the duration of each benchmark group
// ---------------------------------------------------------------------------
struct BenchFixture {
    proxy_addr: SocketAddr,
    backend_task: tokio::task::JoinHandle<()>,
    proxy_task: tokio::task::JoinHandle<()>,
    /// Temp files must stay alive as long as the proxy reads them.
    _cert_file: tempfile::NamedTempFile,
    _key_file: tempfile::NamedTempFile,
}

impl BenchFixture {
    async fn setup() -> Self {
        // 1. Start the plain-HTTP backend (proxy forwards to it without TLS)
        let (backend_task, backend_addr) = start_backend().await;

        // 2. Generate a self-signed TLS cert for the proxy's listen port
        let (cert_file, key_file) = generate_cert_files();

        // 3. Pick a free port for the proxy
        let proxy_port = free_port();
        let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}")
            .parse()
            .unwrap_or_else(|e| panic!("invalid proxy addr: {e}"));
        let backend_address = backend_addr.to_string();

        // 4. Build proxy config with two routes:
        //    /bench/fp  → fingerprinting ON  (measures overhead)
        //    /bench/nofp → fingerprinting OFF (baseline)
        let config = Arc::new(Config {
            listen: proxy_addr,
            backends: vec![Backend { address: backend_address.clone(), http_version: None }],
            routes: vec![
                Route {
                    prefix: "/bench/fp".to_string(),
                    backend: backend_address.clone(),
                    fingerprinting: true,
                    force_new_connection: false,
                    replace_path: Some("/".to_string()),
                    rate_limit: None,
                    headers: None,
                },
                Route {
                    prefix: "/bench/nofp".to_string(),
                    backend: backend_address.clone(),
                    fingerprinting: false,
                    force_new_connection: false,
                    replace_path: Some("/".to_string()),
                    rate_limit: None,
                    headers: None,
                },
                Route {
                    prefix: "/".to_string(),
                    backend: backend_address,
                    fingerprinting: true,
                    force_new_connection: false,
                    replace_path: None,
                    rate_limit: None,
                    headers: None,
                },
            ],
            tls: Some(TlsConfig {
                cert_path: cert_file.path().to_string_lossy().into_owned(),
                key_path: key_file.path().to_string_lossy().into_owned(),
                alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                watch_delay_secs: 60,
                options: Default::default(),
                client_auth: Default::default(),
                session_resumption: Default::default(),
            }),
            fingerprint: FingerprintConfig {
                tls_enabled: true,
                http_enabled: true,
                tcp_enabled: false, // eBPF not available in bench environment
                max_capture: 64 * 1024,
            },
            logging: LoggingConfig { level: "warn".to_string(), show_target: false },
            timeout: TimeoutConfig {
                connect_ms: 5000,
                idle_ms: 600_000, // 10 min - bench groups share a connection pool
                shutdown_secs: 5,
                tls_handshake_secs: 10,
                connection_handling_secs: 600, // 10 min - each group runs ~15s warmup + 15s measure
                keep_alive: KeepAliveConfig::default(),
            },
            security: SecurityConfig::default(),
            telemetry: TelemetryConfig { metrics_port: None, otel_log_level: "warn".to_string() },
            headers: None,
            preserve_host: false,
        });

        // 5. Start proxy in a background task
        let proxy_task = tokio::spawn(async move {
            let _ = huginn_proxy_lib::run(config, None, None).await;
        });

        // 6. Wait for proxy to be ready (retry until it accepts connections)
        wait_for_ready(proxy_addr).await;

        BenchFixture {
            proxy_addr,
            backend_task,
            proxy_task,
            _cert_file: cert_file,
            _key_file: key_file,
        }
    }

    fn teardown(self) {
        self.proxy_task.abort();
        self.backend_task.abort();
    }
}

// ---------------------------------------------------------------------------
// Benchmark 1: HTTP/1.1 round-trip latency (single request per iteration)
// ---------------------------------------------------------------------------
fn bench_http1_latency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| panic!("failed to create tokio runtime: {e}"));
    let fixture = rt.block_on(BenchFixture::setup());
    let proxy_url = format!("https://{}/bench/fp", fixture.proxy_addr);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|e| panic!("failed to build reqwest client: {e}"));

    let mut group = c.benchmark_group("http1_latency");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("single_request_fingerprinting_on", |b| {
        b.iter(|| {
            rt.block_on(async {
                let resp = client
                    .get(&proxy_url)
                    .send()
                    .await
                    .unwrap_or_else(|e| panic!("request failed: {e}"));
                assert!(resp.status().is_success(), "proxy returned non-2xx: {}", resp.status());
                assert_fingerprint_ja4(&resp);
                resp
            })
        })
    });

    group.finish();
    fixture.teardown();
}

// ---------------------------------------------------------------------------
// Benchmark 2: HTTP/2 round-trip latency (single request per iteration)
// ---------------------------------------------------------------------------
fn bench_http2_latency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| panic!("failed to create tokio runtime: {e}"));
    let fixture = rt.block_on(BenchFixture::setup());
    let proxy_url = format!("https://{}/bench/fp", fixture.proxy_addr);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|e| panic!("failed to build reqwest client: {e}"));

    let mut group = c.benchmark_group("http2_latency");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("single_request_fingerprinting_on", |b| {
        b.iter(|| {
            rt.block_on(async {
                let resp = client
                    .get(&proxy_url)
                    .send()
                    .await
                    .unwrap_or_else(|e| panic!("request failed: {e}"));
                assert!(resp.status().is_success());
                assert_fingerprint_ja4(&resp);
                assert_fingerprint_akamai(&resp);
                resp
            })
        })
    });

    group.finish();
    fixture.teardown();
}

// ---------------------------------------------------------------------------
// Benchmark 3: Fingerprinting overhead
// Compares /bench/fp (fingerprinting on) vs /bench/nofp (off) for both
// HTTP/1.1 and HTTP/2. The delta between the two routes is the real cost
// of JA4 + Akamai extraction under identical conditions.
// ---------------------------------------------------------------------------
fn bench_fingerprinting_overhead(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| panic!("failed to create tokio runtime: {e}"));
    let fixture = rt.block_on(BenchFixture::setup());
    let proxy_addr = fixture.proxy_addr;

    let client_h1 = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|e| panic!("failed to build H1 client: {e}"));

    let client_h2 = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|e| panic!("failed to build H2 client: {e}"));

    let mut group = c.benchmark_group("fingerprinting_overhead");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Elements(1));

    let url_fp = format!("https://{proxy_addr}/bench/fp");
    let url_nofp = format!("https://{proxy_addr}/bench/nofp");

    // HTTP/1.1 pair - measures JA4-only overhead (no Akamai on H1)
    group.bench_function("http1_with_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                client_h1
                    .get(&url_fp)
                    .send()
                    .await
                    .unwrap_or_else(|e| panic!("request failed: {e}"))
            })
        })
    });

    group.bench_function("http1_without_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                client_h1
                    .get(&url_nofp)
                    .send()
                    .await
                    .unwrap_or_else(|e| panic!("request failed: {e}"))
            })
        })
    });

    // HTTP/2 pair - measures JA4 + Akamai overhead together
    group.bench_function("http2_with_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                client_h2
                    .get(&url_fp)
                    .send()
                    .await
                    .unwrap_or_else(|e| panic!("request failed: {e}"))
            })
        })
    });

    group.bench_function("http2_without_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                client_h2
                    .get(&url_nofp)
                    .send()
                    .await
                    .unwrap_or_else(|e| panic!("request failed: {e}"))
            })
        })
    });

    group.finish();
    fixture.teardown();
}

// ---------------------------------------------------------------------------
// Benchmark 4: Concurrency scaling
// Measures cold throughput (new TLS connection per task) at c10 and c50.
// Each iteration spawns N tasks, each building its own client (one TLS
// handshake per task), so the result reflects proxy capacity under fresh
// connections - different from the warm latency benchmarks above.
// Covers both HTTP/1.1 and HTTP/2 to compare protocol scaling behaviour.
// ---------------------------------------------------------------------------
fn bench_concurrency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new()
        .unwrap_or_else(|e| panic!("failed to create tokio runtime: {e}"));
    let fixture = rt.block_on(BenchFixture::setup());
    let proxy_addr = fixture.proxy_addr;

    let mut group = c.benchmark_group("concurrency_scaling");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(20));

    for concurrency in [10usize, 50].iter() {
        let n = *concurrency;
        group.throughput(Throughput::Elements(n as u64));

        // HTTP/1.1 - one TCP+TLS connection per task, one request per connection
        group.bench_with_input(BenchmarkId::new("http1_c", concurrency), concurrency, |b, &n| {
            let url = format!("https://{proxy_addr}/bench/fp");
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = Vec::with_capacity(n);
                    for _ in 0..n {
                        let url = url.clone();
                        handles.push(tokio::spawn(async move {
                            let client = reqwest::Client::builder()
                                .danger_accept_invalid_certs(true)
                                .timeout(Duration::from_secs(10))
                                .build()
                                .unwrap_or_else(|e| panic!("failed to build H1 client: {e}"));
                            client.get(&url).send().await.is_ok()
                        }));
                    }
                    let mut success = 0usize;
                    for h in handles {
                        if h.await.unwrap_or(false) {
                            success = success.saturating_add(1);
                        }
                    }
                    success
                })
            })
        });

        // HTTP/2 - one TCP+TLS connection per task (no multiplexing across tasks)
        group.bench_with_input(BenchmarkId::new("http2_c", concurrency), concurrency, |b, &n| {
            let url = format!("https://{proxy_addr}/bench/fp");
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = Vec::with_capacity(n);
                    for _ in 0..n {
                        let url = url.clone();
                        handles.push(tokio::spawn(async move {
                            let client = reqwest::Client::builder()
                                .danger_accept_invalid_certs(true)
                                .http2_prior_knowledge()
                                .timeout(Duration::from_secs(10))
                                .build()
                                .unwrap_or_else(|e| panic!("failed to build H2 client: {e}"));
                            client.get(&url).send().await.is_ok()
                        }));
                    }
                    let mut success = 0usize;
                    for h in handles {
                        if h.await.unwrap_or(false) {
                            success = success.saturating_add(1);
                        }
                    }
                    success
                })
            })
        });
    }

    group.finish();
    fixture.teardown();
}

// ---------------------------------------------------------------------------
// Fingerprint assertion helpers
//
// These verify both presence AND value of fingerprinting headers.
// If the value changes (e.g., after a reqwest/rustls update), the bench panics
// with a clear message pointing to the capture test.
// ---------------------------------------------------------------------------

fn assert_fingerprint_ja4(resp: &reqwest::Response) {
    let value = resp
        .headers()
        .get(HEADER_JA4)
        .unwrap_or_else(|| panic!("missing {HEADER_JA4} header - fingerprinting may be broken"))
        .to_str()
        .unwrap_or_else(|e| panic!("non-UTF8 JA4 header: {e}"));
    assert_eq!(
        value, EXPECTED_JA4,
        "JA4 fingerprint changed (reqwest/rustls update?)\n\
         Re-run: cargo test -p huginn-proxy-lib --test capture_fixtures -- --nocapture\n\
         Then update EXPECTED_JA4 in bench_proxy.rs"
    );
}

fn assert_fingerprint_akamai(resp: &reqwest::Response) {
    let value = resp
        .headers()
        .get(HEADER_AKAMAI)
        .unwrap_or_else(|| {
            panic!("missing {HEADER_AKAMAI} header - HTTP/2 fingerprinting may be broken")
        })
        .to_str()
        .unwrap_or_else(|e| panic!("non-UTF8 Akamai header: {e}"));
    assert_eq!(
        value, EXPECTED_AKAMAI,
        "Akamai fingerprint changed (h2 crate update?)\n\
         Re-run: cargo test -p huginn-proxy-lib --test capture_fixtures -- --nocapture\n\
         Then update EXPECTED_AKAMAI in bench_proxy.rs"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Start a plain HTTP/1.1 Hyper backend that echoes fingerprinting headers back
/// as response headers. This lets the benchmark verify that the proxy actually
/// extracted and injected the fingerprints without modifying the proxy itself.
async fn start_backend() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("failed to bind backend listener: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("failed to get backend addr: {e}"));

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let mut resp = Response::new(Full::new(Bytes::from("ok")));
                    // Echo fingerprinting headers so the benchmark can assert on them
                    for name in [HEADER_JA4, HEADER_AKAMAI] {
                        if let Some(value) = req.headers().get(name) {
                            resp.headers_mut().insert(
                                hyper::header::HeaderName::from_bytes(name.as_bytes())
                                    .unwrap_or_else(|e| panic!("invalid header name {name}: {e}")),
                                value.clone(),
                            );
                        }
                    }
                    Ok::<_, Infallible>(resp)
                });
                let _ = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    (task, addr)
}

/// Find a free TCP port by binding to :0, reading the port, then releasing it.
/// There is a small race window, but it is acceptable for benchmarks on localhost.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("failed to bind for port probe: {e}"));
    l.local_addr()
        .unwrap_or_else(|e| panic!("failed to get port: {e}"))
        .port()
}

/// Generate a self-signed TLS cert/key pair and write them to temp files.
fn generate_cert_files() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .unwrap_or_else(|e| panic!("failed to generate self-signed cert: {e}"));

    let cert_file = tempfile::NamedTempFile::new()
        .unwrap_or_else(|e| panic!("failed to create cert tempfile: {e}"));
    let key_file = tempfile::NamedTempFile::new()
        .unwrap_or_else(|e| panic!("failed to create key tempfile: {e}"));

    std::fs::write(cert_file.path(), cert.pem())
        .unwrap_or_else(|e| panic!("failed to write cert: {e}"));
    std::fs::write(key_file.path(), signing_key.serialize_pem())
        .unwrap_or_else(|e| panic!("failed to write key: {e}"));

    (cert_file, key_file)
}

/// Poll the proxy until it accepts a TCP connection, up to 5 seconds.
async fn wait_for_ready(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(5))
        .unwrap_or_else(|| panic!("deadline arithmetic overflow"));
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            // Give TLS acceptor a moment to initialize
            tokio::time::sleep(Duration::from_millis(50)).await;
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("proxy at {addr} did not become ready within 5 seconds");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

criterion_group!(
    proxy_benches,
    bench_http1_latency,
    bench_http2_latency,
    bench_fingerprinting_overhead,
    bench_concurrency,
);
criterion_main!(proxy_benches);
