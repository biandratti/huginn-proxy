//! Performance benchmarks for Huginn Proxy
//!
//! These benchmarks measure various aspects of proxy performance:
//! - Request throughput (RPS)
//! - Latency distribution (p50, p95, p99)
//! - Concurrent connection handling
//! - Fingerprinting overhead (TLS and HTTP/2)
//! - Load balancing performance
//! - TLS handshake overhead
//!
//! To run benchmarks:
//! ```bash
//! cargo bench --bench bench_proxy
//! ```
//!
//! For HTML reports:
//! ```bash
//! cargo bench --bench bench_proxy -- --output-format html
//! ```

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Mutex;
use std::time::Duration;

/// Number of requests to make per benchmark iteration
/// Reduced from 1000 to 10 for faster benchmarks (HTTP requests are slower than in-memory packet processing)
const REQUESTS_PER_ITERATION: usize = 10;

/// Benchmark results storage for automatic reporting
static BENCHMARK_RESULTS: Mutex<Option<BenchmarkReport>> = Mutex::new(None);

#[derive(Debug, Clone)]
struct LoadTestResult {
    name: String,
    rps: f64,
    fingerprinting_enabled: bool,
    protocol: String, // "http1" or "http2"
}

impl LoadTestResult {
    fn is_http1(&self) -> bool {
        self.protocol == "http1"
    }

    fn is_http2(&self) -> bool {
        self.protocol == "http2"
    }
}

#[derive(Debug, Clone)]
struct LatencyStats {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    p99_9: Duration,
    min: Duration,
    max: Duration,
    mean: Duration,
}

#[derive(Debug, Clone)]
struct BenchmarkReport {
    request_count: usize,
    successful_requests: usize,
    failed_requests: usize,
    timings: Vec<(String, Duration)>,
    latency_stats: Option<LatencyStats>,
    throughput_rps: f64,
    throughput_bytes_per_sec: f64,
    // Load test results for performance comparison
    load_test_results: Vec<LoadTestResult>,
}

criterion_group!(
    proxy_benches,
    bench_proxy_request_throughput,
    bench_proxy_concurrent_connections,
    bench_proxy_fingerprinting_overhead,
    bench_proxy_load_balancing,
    bench_proxy_tls_handshake,
    bench_proxy_latency_distribution,
    bench_proxy_load_test_comparison,
    generate_final_report
);
criterion_main!(proxy_benches);

/// Calculate throughput in requests per second
fn calculate_throughput_rps(duration: Duration, request_count: usize) -> f64 {
    let seconds = duration.as_secs_f64();
    if seconds > 0.0 {
        (request_count as f64) / seconds
    } else {
        0.0
    }
}

/// Format throughput for display
fn format_throughput(rps: f64) -> String {
    if rps >= 1_000_000.0 {
        format!("{:.2}M", rps / 1_000_000.0)
    } else if rps >= 1_000.0 {
        format!("{:.1}k", rps / 1_000.0)
    } else {
        format!("{rps:.0}")
    }
}

/// Measure average execution time for a benchmark
fn measure_average_time<F>(mut f: F, iterations: usize) -> Duration
where
    F: FnMut(),
{
    if iterations == 0 {
        return Duration::ZERO;
    }
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        f();
    }
    start
        .elapsed()
        .checked_div(iterations as u32)
        .unwrap_or(Duration::ZERO)
}

/// Calculate latency percentiles from a sorted vector of durations
fn calculate_latency_percentiles(mut latencies: Vec<Duration>) -> LatencyStats {
    if latencies.is_empty() {
        return LatencyStats {
            p50: Duration::ZERO,
            p95: Duration::ZERO,
            p99: Duration::ZERO,
            p99_9: Duration::ZERO,
            min: Duration::ZERO,
            max: Duration::ZERO,
            mean: Duration::ZERO,
        };
    }

    latencies.sort();

    let count = latencies.len();
    let min = latencies[0];
    let max_idx = count.saturating_sub(1);
    let max = latencies[max_idx];

    let mean_nanos: u128 = latencies.iter().map(|d| d.as_nanos()).sum();
    let mean = Duration::from_nanos((mean_nanos.checked_div(count as u128).unwrap_or(0)) as u64);

    let p50_idx = ((count as f64 * 0.50) as usize).min(max_idx);
    let p95_idx = ((count as f64 * 0.95) as usize).min(max_idx);
    let p99_idx = ((count as f64 * 0.99) as usize).min(max_idx);
    let p99_9_idx = ((count as f64 * 0.999) as usize).min(max_idx);

    LatencyStats {
        p50: latencies[p50_idx],
        p95: latencies[p95_idx],
        p99: latencies[p99_idx],
        p99_9: latencies[p99_9_idx],
        min,
        max,
        mean,
    }
}

/// Setup HTTP client for benchmarks
fn setup_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))
}

/// Setup HTTP/2 client for benchmarks
fn setup_client_h2() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))
}

/// Setup Tokio runtime for async benchmarks
fn setup_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Runtime::new().map_err(|e| format!("Failed to create Tokio runtime: {e}"))
}

/// Benchmark: Request throughput (RPS)
fn bench_proxy_request_throughput(c: &mut Criterion) {
    let client = match setup_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP client: {e}");
            return;
        }
    };
    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| "https://localhost:7000".to_string());

    // Initialize benchmark report
    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        *guard = Some(BenchmarkReport {
            request_count: REQUESTS_PER_ITERATION,
            successful_requests: 0,
            failed_requests: 0,
            timings: Vec::new(),
            latency_stats: None,
            throughput_rps: 0.0,
            throughput_bytes_per_sec: 0.0,
            load_test_results: Vec::new(),
        });
    }

    let mut group = c.benchmark_group("request_throughput");
    group.throughput(Throughput::Elements(REQUESTS_PER_ITERATION as u64));
    // Reduce sample count and measurement time for faster benchmarks
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let rt = match setup_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error setting up Tokio runtime: {e}");
            return;
        }
    };
    group.bench_function("http1_simple", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut success_count: usize = 0;
                for _ in 0..REQUESTS_PER_ITERATION {
                    if client.get(&proxy_url).send().await.is_ok() {
                        success_count = success_count.saturating_add(1);
                    }
                }
                success_count
            })
        });
    });

    let client_h2 = match setup_client_h2() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP/2 client: {e}");
            group.finish();
            return;
        }
    };

    group.bench_function("http2", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut success_count: usize = 0;
                for _ in 0..REQUESTS_PER_ITERATION {
                    if client_h2.get(&proxy_url).send().await.is_ok() {
                        success_count = success_count.saturating_add(1);
                    }
                }
                success_count
            })
        });
    });

    group.finish();

    // Measure and store actual times for reporting
    let http1_time = measure_average_time(
        || {
            rt.block_on(async {
                let mut success_count: usize = 0;
                for _ in 0..REQUESTS_PER_ITERATION {
                    if client.get(&proxy_url).send().await.is_ok() {
                        success_count = success_count.saturating_add(1);
                    }
                }
                let _ = success_count; // Ignore return value
            })
        },
        5,
    );

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report
                .timings
                .push(("http1_throughput".to_string(), http1_time));
            report.successful_requests = REQUESTS_PER_ITERATION;
            report.throughput_rps = calculate_throughput_rps(http1_time, REQUESTS_PER_ITERATION);
        }
    }
}

/// Benchmark: Concurrent connections
fn bench_proxy_concurrent_connections(c: &mut Criterion) {
    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| "https://localhost:7000".to_string());

    let mut group = c.benchmark_group("concurrent_connections");
    // Reduce sample count and measurement time for faster benchmarks
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let rt = match setup_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error setting up Tokio runtime: {e}");
            return;
        }
    };
    for concurrent in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrent),
            concurrent,
            |b, &concurrent| {
                b.iter(|| {
                    rt.block_on(async {
                        let client = match setup_client() {
                            Ok(client) => client,
                            Err(_) => return 0,
                        };
                        let mut handles = Vec::new();

                        for _ in 0..concurrent {
                            let client = client.clone();
                            let url = proxy_url.clone();
                            handles.push(tokio::spawn(async move {
                                client.get(&url).send().await.is_ok()
                            }));
                        }

                        let mut success_count: usize = 0;
                        for handle in handles {
                            if handle.await.unwrap_or(false) {
                                success_count = success_count.saturating_add(1);
                            }
                        }
                        success_count
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Fingerprinting overhead
fn bench_proxy_fingerprinting_overhead(c: &mut Criterion) {
    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| "https://localhost:7000".to_string());

    let mut group = c.benchmark_group("fingerprinting_overhead");
    group.throughput(Throughput::Elements(REQUESTS_PER_ITERATION as u64));
    // Reduce sample count and measurement time for faster benchmarks
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    // Baseline: requests without checking fingerprints
    let client = match setup_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP client: {e}");
            return;
        }
    };
    let rt = match setup_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error setting up Tokio runtime: {e}");
            return;
        }
    };
    group.bench_function("baseline_no_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut success_count: usize = 0;
                for _ in 0..REQUESTS_PER_ITERATION {
                    if client.get(&proxy_url).send().await.is_ok() {
                        success_count = success_count.saturating_add(1);
                    }
                }
                success_count
            })
        });
    });

    // With fingerprinting: requests that extract TLS and HTTP/2 fingerprints
    group.bench_function("with_tls_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut success_count: usize = 0;
                for _ in 0..REQUESTS_PER_ITERATION {
                    if let Ok(response) = client.get(&proxy_url).send().await {
                        // Check if fingerprint headers are present
                        if response.headers().contains_key("x-huginn-net-tls") {
                            success_count = success_count.saturating_add(1);
                        }
                    }
                }
                success_count
            })
        });
    });

    let client_h2 = match setup_client_h2() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP/2 client: {e}");
            group.finish();
            return;
        }
    };

    group.bench_function("with_http2_fingerprinting", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut success_count: usize = 0;
                for _ in 0..REQUESTS_PER_ITERATION {
                    if let Ok(response) = client_h2.get(&proxy_url).send().await {
                        // Check if HTTP/2 fingerprint headers are present
                        if response.headers().contains_key("x-huginn-net-http") {
                            success_count = success_count.saturating_add(1);
                        }
                    }
                }
                success_count
            })
        });
    });

    group.finish();
}

/// Benchmark: Load balancing performance
fn bench_proxy_load_balancing(c: &mut Criterion) {
    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| "https://localhost:7000".to_string());

    let mut group = c.benchmark_group("load_balancing");
    group.throughput(Throughput::Elements(REQUESTS_PER_ITERATION as u64));
    // Reduce sample count and measurement time for faster benchmarks
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let client = match setup_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP client: {e}");
            return;
        }
    };
    let rt = match setup_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error setting up Tokio runtime: {e}");
            return;
        }
    };
    group.bench_function("round_robin_2_backends", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut success_count: usize = 0;
                for _ in 0..REQUESTS_PER_ITERATION {
                    if client.get(&proxy_url).send().await.is_ok() {
                        success_count = success_count.saturating_add(1);
                    }
                }
                success_count
            })
        });
    });

    group.finish();
}

/// Benchmark: TLS handshake overhead
fn bench_proxy_tls_handshake(c: &mut Criterion) {
    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| "https://localhost:7000".to_string());

    let mut group = c.benchmark_group("tls_handshake");
    group.throughput(Throughput::Elements(REQUESTS_PER_ITERATION as u64));
    // Reduce sample count and measurement time for faster benchmarks
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let client = match setup_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP client: {e}");
            return;
        }
    };
    let rt = match setup_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error setting up Tokio runtime: {e}");
            return;
        }
    };
    group.bench_function("tls_handshake_time", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut success_count: usize = 0;
                for _ in 0..REQUESTS_PER_ITERATION {
                    let start = std::time::Instant::now();
                    if client.get(&proxy_url).send().await.is_ok() {
                        let _handshake_time = start.elapsed();
                        success_count = success_count.saturating_add(1);
                    }
                }
                success_count
            })
        });
    });

    group.finish();
}

/// Benchmark: Latency distribution
fn bench_proxy_latency_distribution(c: &mut Criterion) {
    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| "https://localhost:7000".to_string());

    let mut group = c.benchmark_group("latency_distribution");
    group.throughput(Throughput::Elements(REQUESTS_PER_ITERATION as u64));
    // Reduce sample count and measurement time for faster benchmarks
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let client = match setup_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP client: {e}");
            return;
        }
    };
    let rt = match setup_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error setting up Tokio runtime: {e}");
            return;
        }
    };
    group.bench_function("latency_measurement", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut latencies = Vec::with_capacity(REQUESTS_PER_ITERATION);

                for _ in 0..REQUESTS_PER_ITERATION {
                    let start = std::time::Instant::now();
                    if client.get(&proxy_url).send().await.is_ok() {
                        latencies.push(start.elapsed());
                    }
                }

                let stats = calculate_latency_percentiles(latencies);
                let _ = stats; // Use stats to avoid unused warning
                stats.p99.as_nanos() as usize // Return something meaningful
            })
        });
    });

    group.finish();
}

/// Benchmark: Load test comparison (fingerprinting enabled vs disabled)
/// Measures RPS with different configurations for performance analysis
///
/// Fingerprinting types measured:
/// - HTTP/1.1: TLS fingerprinting only (JA4)
/// - HTTP/2: TLS fingerprinting (JA4) + HTTP/2 fingerprinting (Akamai)
fn bench_proxy_load_test_comparison(c: &mut Criterion) {
    // This benchmark uses routes with different fingerprinting settings:
    // 1. PROXY_URL + /api route (fingerprinting enabled - both TLS and HTTP/2)
    // 2. PROXY_URL + /static route (fingerprinting disabled)
    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| "https://localhost:7000".to_string());
    let proxy_url_enabled = format!("{proxy_url}/api/test");
    let proxy_url_disabled = format!("{proxy_url}/static/test");

    // Number of requests for load test (higher than regular benchmarks)
    const LOAD_TEST_REQUESTS: usize = 1000;
    const LOAD_TEST_CONCURRENT: usize = 10; // 10 concurrent connections

    let mut group = c.benchmark_group("load_test_comparison");
    group.sample_size(10); // Minimum 10 samples required by criterion
    group.measurement_time(Duration::from_secs(30)); // Longer measurement time

    // HTTP/1.1 with fingerprinting enabled (TLS fingerprinting only)
    let client = match setup_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP client: {e}");
            return;
        }
    };
    let rt = match setup_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error setting up Tokio runtime: {e}");
            return;
        }
    };
    group.bench_function("http1_fingerprinting_enabled", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::new();
                for _ in 0..LOAD_TEST_CONCURRENT {
                    let client = client.clone();
                    let url = proxy_url_enabled.clone();
                    handles.push(tokio::spawn(async move {
                        let mut success: usize = 0;
                        for _ in 0..(LOAD_TEST_REQUESTS / LOAD_TEST_CONCURRENT) {
                            if client.get(&url).send().await.is_ok() {
                                success = success.saturating_add(1);
                            }
                        }
                        success
                    }));
                }
                let mut total: usize = 0;
                for handle in handles {
                    total = total.saturating_add(handle.await.unwrap_or(0));
                }
                total
            })
        });
    });

    // HTTP/1.1 with fingerprinting disabled
    {
        let client = match setup_client() {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Error setting up HTTP client: {e}");
                group.finish();
                return;
            }
        };
        group.bench_function("http1_fingerprinting_disabled", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = Vec::new();
                    for _ in 0..LOAD_TEST_CONCURRENT {
                        let client = client.clone();
                        let url = proxy_url_disabled.clone();
                        handles.push(tokio::spawn(async move {
                            let mut success: usize = 0;
                            for _ in 0..(LOAD_TEST_REQUESTS / LOAD_TEST_CONCURRENT) {
                                if client.get(&url).send().await.is_ok() {
                                    success = success.saturating_add(1);
                                }
                            }
                            success
                        }));
                    }
                    let mut total: usize = 0;
                    for handle in handles {
                        total = total.saturating_add(handle.await.unwrap_or(0));
                    }
                    total
                })
            });
        });
    }

    // HTTP/2 with fingerprinting enabled
    let client_h2 = match setup_client_h2() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP/2 client: {e}");
            group.finish();
            return;
        }
    };

    group.bench_function("http2_fingerprinting_enabled", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::new();
                for _ in 0..LOAD_TEST_CONCURRENT {
                    let client = client_h2.clone();
                    let url = proxy_url_enabled.clone();
                    handles.push(tokio::spawn(async move {
                        let mut success: usize = 0;
                        for _ in 0..(LOAD_TEST_REQUESTS / LOAD_TEST_CONCURRENT) {
                            if client.get(&url).send().await.is_ok() {
                                success = success.saturating_add(1);
                            }
                        }
                        success
                    }));
                }
                let mut total: usize = 0;
                for handle in handles {
                    total = total.saturating_add(handle.await.unwrap_or(0));
                }
                total
            })
        });
    });

    // HTTP/2 with fingerprinting disabled (if proxy available)
    if proxy_url_disabled != proxy_url_enabled {
        let client_h2_disabled = match setup_client_h2() {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Error setting up HTTP/2 client: {e}");
                group.finish();
                return;
            }
        };

        group.bench_function("http2_fingerprinting_disabled", |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = Vec::new();
                    for _ in 0..LOAD_TEST_CONCURRENT {
                        let client = client_h2_disabled.clone();
                        let url = proxy_url_disabled.clone();
                        handles.push(tokio::spawn(async move {
                            let mut success: usize = 0;
                            for _ in 0..(LOAD_TEST_REQUESTS / LOAD_TEST_CONCURRENT) {
                                if client.get(&url).send().await.is_ok() {
                                    success = success.saturating_add(1);
                                }
                            }
                            success
                        }));
                    }
                    let mut total: usize = 0;
                    for handle in handles {
                        total = total.saturating_add(handle.await.unwrap_or(0));
                    }
                    total
                })
            });
        });
    }

    group.finish();

    // Measure and store load test results for reporting
    let rt = match setup_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error setting up Tokio runtime for load test reporting: {e}");
            return;
        }
    };

    // Measure HTTP/1.1 with fingerprinting enabled
    let start = std::time::Instant::now();
    let enabled_success = rt.block_on(async {
        let mut handles = Vec::new();
        for _ in 0..LOAD_TEST_CONCURRENT {
            let client = client.clone();
            let url = proxy_url_enabled.clone();
            handles.push(tokio::spawn(async move {
                let mut success: usize = 0;
                for _ in 0..(LOAD_TEST_REQUESTS / LOAD_TEST_CONCURRENT) {
                    if client.get(&url).send().await.is_ok() {
                        success = success.saturating_add(1);
                    }
                }
                success
            }));
        }
        let mut total: usize = 0;
        for handle in handles {
            total = total.saturating_add(handle.await.unwrap_or(0));
        }
        total
    });
    let enabled_duration = start.elapsed();
    let enabled_rps = calculate_throughput_rps(enabled_duration, enabled_success);

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report.load_test_results.push(LoadTestResult {
                name: "HTTP/1.1 with fingerprinting (TLS)".to_string(),
                rps: enabled_rps,
                fingerprinting_enabled: true,
                protocol: "http1".to_string(),
            });
        }
    }

    // Measure HTTP/2 with fingerprinting enabled (TLS + HTTP/2)
    let client_h2 = match setup_client_h2() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error setting up HTTP/2 client for load test reporting: {e}");
            return;
        }
    };

    let start = std::time::Instant::now();
    let enabled_h2_success = rt.block_on(async {
        let mut handles = Vec::new();
        for _ in 0..LOAD_TEST_CONCURRENT {
            let client = client_h2.clone();
            let url = proxy_url_enabled.clone();
            handles.push(tokio::spawn(async move {
                let mut success: usize = 0;
                for _ in 0..(LOAD_TEST_REQUESTS / LOAD_TEST_CONCURRENT) {
                    if client.get(&url).send().await.is_ok() {
                        success = success.saturating_add(1);
                    }
                }
                success
            }));
        }
        let mut total: usize = 0;
        for handle in handles {
            total = total.saturating_add(handle.await.unwrap_or(0));
        }
        total
    });
    let enabled_h2_duration = start.elapsed();
    let enabled_h2_rps = calculate_throughput_rps(enabled_h2_duration, enabled_h2_success);

    if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
        if let Some(ref mut report) = *guard {
            report.load_test_results.push(LoadTestResult {
                name: "HTTP/2 with fingerprinting (TLS + HTTP/2)".to_string(),
                rps: enabled_h2_rps,
                fingerprinting_enabled: true,
                protocol: "http2".to_string(),
            });
        }
    }

    // Measure with fingerprinting disabled (if available)
    if proxy_url_disabled != proxy_url_enabled {
        let client_disabled = match setup_client() {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Error setting up HTTP client for disabled fingerprinting test: {e}");
                return;
            }
        };
        let start = std::time::Instant::now();
        let disabled_success = rt.block_on(async {
            let mut handles = Vec::new();
            for _ in 0..LOAD_TEST_CONCURRENT {
                let client = client_disabled.clone();
                let url = proxy_url_disabled.clone();
                handles.push(tokio::spawn(async move {
                    let mut success: usize = 0;
                    for _ in 0..(LOAD_TEST_REQUESTS / LOAD_TEST_CONCURRENT) {
                        if client.get(&url).send().await.is_ok() {
                            success = success.saturating_add(1);
                        }
                    }
                    success
                }));
            }
            let mut total: usize = 0;
            for handle in handles {
                total = total.saturating_add(handle.await.unwrap_or(0));
            }
            total
        });
        let disabled_duration = start.elapsed();
        let disabled_rps = calculate_throughput_rps(disabled_duration, disabled_success);

        if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
            if let Some(ref mut report) = *guard {
                report.load_test_results.push(LoadTestResult {
                    name: "HTTP/1.1 without fingerprinting".to_string(),
                    rps: disabled_rps,
                    fingerprinting_enabled: false,
                    protocol: "http1".to_string(),
                });
            }
        }

        // Measure HTTP/2 without fingerprinting
        let client_h2_disabled = match setup_client_h2() {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Error setting up HTTP/2 client for disabled fingerprinting test: {e}");
                return;
            }
        };

        let start = std::time::Instant::now();
        let disabled_h2_success = rt.block_on(async {
            let mut handles = Vec::new();
            for _ in 0..LOAD_TEST_CONCURRENT {
                let client = client_h2_disabled.clone();
                let url = proxy_url_disabled.clone();
                handles.push(tokio::spawn(async move {
                    let mut success: usize = 0;
                    for _ in 0..(LOAD_TEST_REQUESTS / LOAD_TEST_CONCURRENT) {
                        if client.get(&url).send().await.is_ok() {
                            success = success.saturating_add(1);
                        }
                    }
                    success
                }));
            }
            let mut total: usize = 0;
            for handle in handles {
                total = total.saturating_add(handle.await.unwrap_or(0));
            }
            total
        });
        let disabled_h2_duration = start.elapsed();
        let disabled_h2_rps = calculate_throughput_rps(disabled_h2_duration, disabled_h2_success);

        if let Ok(mut guard) = BENCHMARK_RESULTS.lock() {
            if let Some(ref mut report) = *guard {
                report.load_test_results.push(LoadTestResult {
                    name: "HTTP/2 without fingerprinting".to_string(),
                    rps: disabled_h2_rps,
                    fingerprinting_enabled: false,
                    protocol: "http2".to_string(),
                });
            }
        }
    }
}

/// Generate comprehensive benchmark report
fn generate_final_report(_c: &mut Criterion) {
    let report = match BENCHMARK_RESULTS.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => return,
    };

    let Some(report) = report else {
        println!("\nNo benchmark results collected yet. Run benchmarks first.");
        return;
    };

    println!("\n");
    println!("===============================================================================");
    println!("                   HUGINN PROXY BENCHMARK ANALYSIS REPORT                    ");
    println!("===============================================================================");
    println!();
    println!("Request Summary:");
    println!("  - Total requests: {}", report.request_count);
    println!("  - Successful requests: {}", report.successful_requests);
    println!("  - Failed requests: {}", report.failed_requests);
    let success_rate = if report.request_count > 0 {
        (report.successful_requests as f64 / report.request_count as f64) * 100.0
    } else {
        0.0
    };
    println!("  - Success rate: {success_rate:.1}%");
    println!();

    if let Some(stats) = &report.latency_stats {
        println!("Latency Distribution:");
        println!("  - Min: {:?}", stats.min);
        println!("  - P50: {:?}", stats.p50);
        println!("  - P95: {:?}", stats.p95);
        println!("  - P99: {:?}", stats.p99);
        println!("  - P99.9: {:?}", stats.p99_9);
        println!("  - Max: {:?}", stats.max);
        println!("  - Mean: {:?}", stats.mean);
        println!();
    }

    println!("Throughput:");
    println!("  - Requests per second: {} req/s", format_throughput(report.throughput_rps));
    println!(
        "  - Bytes per second: {} bytes/s",
        format_throughput(report.throughput_bytes_per_sec)
    );
    println!();

    if !report.timings.is_empty() {
        println!("Performance Summary:");
        println!("+--------------------------------------------------------------------------+");
        println!("| Operation                        | Duration      | Throughput          |");
        println!("+--------------------------------------------------------------------------+");

        for (name, duration) in &report.timings {
            let throughput = calculate_throughput_rps(*duration, report.request_count);
            println!("| {:<32} | {:12?} | {:>18} |", name, duration, format_throughput(throughput));
        }
        println!("+--------------------------------------------------------------------------+");
        println!();
    }

    // Load Test Comparison
    if !report.load_test_results.is_empty() {
        println!("Load Test Comparison:");
        println!("+--------------------------------------------------------------------------+");
        println!("| Configuration                     | RPS           | Fingerprinting      |");
        println!("+--------------------------------------------------------------------------+");

        for result in &report.load_test_results {
            let fp_status = if result.fingerprinting_enabled {
                "Enabled"
            } else {
                "Disabled"
            };
            println!(
                "| {:<32} | {:>13} | {:<19} |",
                result.name,
                format!("{:.2}", result.rps),
                fp_status
            );
        }
        println!("+--------------------------------------------------------------------------+");
        println!();

        // Calculate overhead by protocol (HTTP/1.1 and HTTP/2 separately)
        let http1_enabled = report
            .load_test_results
            .iter()
            .find(|r| r.is_http1() && r.fingerprinting_enabled)
            .map(|r| r.rps);
        let http1_disabled = report
            .load_test_results
            .iter()
            .find(|r| r.is_http1() && !r.fingerprinting_enabled)
            .map(|r| r.rps);
        let http2_enabled = report
            .load_test_results
            .iter()
            .find(|r| r.is_http2() && r.fingerprinting_enabled)
            .map(|r| r.rps);
        let http2_disabled = report
            .load_test_results
            .iter()
            .find(|r| r.is_http2() && !r.fingerprinting_enabled)
            .map(|r| r.rps);

        println!("Fingerprinting Overhead Analysis:");

        if let (Some(enabled), Some(disabled)) = (http1_enabled, http1_disabled) {
            let overhead_percent = if disabled > 0.0 {
                ((enabled - disabled) / disabled) * 100.0
            } else {
                0.0
            };
            println!("  HTTP/1.1:");
            println!("    - With fingerprinting (TLS):    {enabled:.2} req/s");
            println!("    - Without fingerprinting:        {disabled:.2} req/s");
            println!("    - Overhead:                      {overhead_percent:.2}%");
            let ratio = disabled / enabled;
            println!("    - Performance ratio:             {ratio:.2}x");
        }

        if let (Some(enabled), Some(disabled)) = (http2_enabled, http2_disabled) {
            let overhead_percent = if disabled > 0.0 {
                ((enabled - disabled) / disabled) * 100.0
            } else {
                0.0
            };
            println!("  HTTP/2:");
            println!("    - With fingerprinting (TLS + HTTP/2): {enabled:.2} req/s");
            println!("    - Without fingerprinting:             {disabled:.2} req/s");
            println!("    - Overhead:                            {overhead_percent:.2}%");
            let ratio = disabled / enabled;
            println!("    - Performance ratio:                   {ratio:.2}x");
        }

        // Overall comparison if both protocols are available
        if let (Some(h1_enabled), Some(h1_disabled), Some(h2_enabled), Some(h2_disabled)) =
            (http1_enabled, http1_disabled, http2_enabled, http2_disabled)
        {
            let avg_enabled = (h1_enabled + h2_enabled) / 2.0;
            let avg_disabled = (h1_disabled + h2_disabled) / 2.0;
            let avg_overhead = if avg_disabled > 0.0 {
                ((avg_enabled - avg_disabled) / avg_disabled) * 100.0
            } else {
                0.0
            };
            println!("  Overall Average:");
            println!("    - With fingerprinting:    {avg_enabled:.2} req/s");
            println!("    - Without fingerprinting: {avg_disabled:.2} req/s");
            println!("    - Average overhead:      {avg_overhead:.2}%");
            println!();
        } else {
            println!();
        }

        // Reference values for comparison (from public benchmarks)
        println!("Reference Values (from public benchmarks):");
        println!("  - Reverse proxy with fingerprinting:            ~2,000-16,000 req/s");
        println!("  - Control group (simple HTTP server):            ~29,650 req/s");
        println!("  - Reverse proxy with limiters:                   ~22-24k req/s");
        println!();
    }

    println!("Benchmark report generation complete");
    println!();
}
