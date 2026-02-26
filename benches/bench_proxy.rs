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
use hyper::Response;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Fingerprint header names (mirrors huginn_proxy_lib::fingerprinting::names)
// ---------------------------------------------------------------------------
const HEADER_JA4: &str = "x-huginn-net-ja4";
const HEADER_AKAMAI: &str = "x-huginn-net-akamai";

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
        let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
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
                idle_ms: 600_000,        // 10 min — bench groups share a connection pool
                shutdown_secs: 5,
                tls_handshake_secs: 10,
                connection_handling_secs: 600, // 10 min — each group runs ~15s warmup + 15s measure
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

        BenchFixture { proxy_addr, backend_task, proxy_task, _cert_file: cert_file, _key_file: key_file }
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fixture = rt.block_on(BenchFixture::setup());
    let proxy_url = format!("https://{}/bench/fp", fixture.proxy_addr);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let mut group = c.benchmark_group("http1_latency");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("single_request_fingerprinting_on", |b| {
        b.iter(|| {
            rt.block_on(async {
                let resp = client.get(&proxy_url).send().await.expect("request failed");
                assert!(resp.status().is_success(), "proxy returned non-2xx: {}", resp.status());
                // Verify fingerprinting headers are present
                assert!(
                    resp.headers().contains_key(HEADER_JA4),
                    "missing {HEADER_JA4} header"
                );
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
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fixture = rt.block_on(BenchFixture::setup());
    let proxy_url = format!("https://{}/bench/fp", fixture.proxy_addr);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let mut group = c.benchmark_group("http2_latency");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("single_request_fingerprinting_on", |b| {
        b.iter(|| {
            rt.block_on(async {
                let resp = client.get(&proxy_url).send().await.expect("request failed");
                assert!(resp.status().is_success());
                // HTTP/2 gets both JA4 and Akamai headers
                assert!(resp.headers().contains_key(HEADER_JA4), "missing {HEADER_JA4}");
                assert!(resp.headers().contains_key(HEADER_AKAMAI), "missing {HEADER_AKAMAI}");
                resp
            })
        })
    });

    group.finish();
    fixture.teardown();
}

// ---------------------------------------------------------------------------
// Benchmark 3: Fingerprinting overhead
// Compares /bench/fp (fingerprinting on) vs /bench/nofp (off)
// The delta is the real cost of JA4 + Akamai extraction.
// ---------------------------------------------------------------------------
fn bench_fingerprinting_overhead(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fixture = rt.block_on(BenchFixture::setup());
    let proxy_addr = fixture.proxy_addr;

    // HTTP/2 client: shows Akamai overhead most clearly
    let client_h2 = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let mut group = c.benchmark_group("fingerprinting_overhead");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Elements(1));

    let url_fp = format!("https://{proxy_addr}/bench/fp");
    let url_nofp = format!("https://{proxy_addr}/bench/nofp");

    group.bench_function("http2_with_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                client_h2.get(&url_fp).send().await.expect("request failed")
            })
        })
    });

    group.bench_function("http2_without_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                client_h2.get(&url_nofp).send().await.expect("request failed")
            })
        })
    });

    group.finish();
    fixture.teardown();
}

// ---------------------------------------------------------------------------
// Benchmark 4: Concurrency scaling
// Measures throughput (RPS) at different concurrency levels.
// ---------------------------------------------------------------------------
fn bench_concurrency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fixture = rt.block_on(BenchFixture::setup());
    let proxy_addr = fixture.proxy_addr;

    let mut group = c.benchmark_group("concurrency_scaling");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(20));

    for concurrency in [1usize, 10, 50].iter() {
        group.throughput(Throughput::Elements(*concurrency as u64));
        group.bench_with_input(
            BenchmarkId::new("http1_concurrent_requests", concurrency),
            concurrency,
            |b, &n| {
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
                                    .unwrap();
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
            },
        );
    }

    group.finish();
    fixture.teardown();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Start a plain HTTP/1.1 Hyper backend that echoes fingerprinting headers back
/// as response headers. This lets the benchmark verify that the proxy actually
/// extracted and injected the fingerprints without modifying the proxy itself.
async fn start_backend() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let mut resp = Response::new(Full::new(Bytes::from("ok")));
                    // Echo fingerprinting headers so the benchmark can assert on them
                    for name in [HEADER_JA4, HEADER_AKAMAI] {
                        if let Some(value) = req.headers().get(name) {
                            resp.headers_mut().insert(
                                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
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
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Generate a self-signed TLS cert/key pair and write them to temp files.
fn generate_cert_files() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();

    let cert_file = tempfile::NamedTempFile::new().unwrap();
    let key_file = tempfile::NamedTempFile::new().unwrap();

    std::fs::write(cert_file.path(), cert.pem()).unwrap();
    std::fs::write(key_file.path(), signing_key.serialize_pem()).unwrap();

    (cert_file, key_file)
}

/// Poll the proxy until it accepts a TCP connection, up to 5 seconds.
async fn wait_for_ready(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
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
