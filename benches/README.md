# Huginn Proxy — Benchmarks

Two benchmark suites with different scopes:

| Suite | File | Scope |
|---|---|---|
| `bench_fingerprinting` | `benches/bench_fingerprinting.rs` | Micro — pure parsing, no network |
| `bench_proxy` | `benches/bench_proxy.rs` | Integration — full proxy round-trip |

---

## Quick start

```bash
# Run all benchmarks
cargo bench -p huginn-proxy-lib

# Run a specific suite
cargo bench --bench bench_fingerprinting
cargo bench --bench bench_proxy

# Save a named baseline (for regression comparison)
cargo bench --bench bench_proxy -- --save-baseline v0_1_0

# Compare against a saved baseline
cargo bench --bench bench_proxy -- --baseline v0_1_0
```

HTML reports are written to `target/criterion/`.

---

## `bench_fingerprinting` — micro benchmarks

Benchmarks the raw parsing speed of each fingerprinting algorithm.
No network, no IO — pure CPU work on hardcoded byte fixtures.

### Benchmarks

| Name | What it measures |
|---|---|
| `akamai_parse_http2_settings_window_update` | `extract_akamai_fingerprint()` on HTTP/2 SETTINGS + WINDOW_UPDATE |
| `ja4_parse_tls_client_hello` | `parse_tls_client_hello()` on a TLS 1.3 ClientHello |

### Fixtures

**HTTP/2** (`HTTP2_CLIENT_FRAMES`): hardcoded bytes representing a real `reqwest`/`h2` client
connection start — connection preface, SETTINGS frame, WINDOW_UPDATE frame.
Values match what the `h2` crate sends by default.

**TLS ClientHello** (`CLIENT_HELLO_BYTES`): a synthetic but structurally valid TLS 1.3
ClientHello with realistic cipher suites, extensions, and a key_share entry.

#### Refreshing the TLS fixture from a real connection

The TLS ClientHello fixture in `bench_fingerprinting.rs` is a synthetic approximation.
To replace it with bytes captured from a real `reqwest` connection, add a test like this
in `huginn-proxy-lib/tests/`:

```rust
// tests/capture_fixtures.rs
#[tokio::test]
async fn capture_tls_client_hello() {
    // Start a TLS server that records the raw bytes before the handshake
    // Print them as a Rust byte array
    // Paste into CLIENT_HELLO_BYTES in bench_fingerprinting.rs
}
```

Running `cargo test -- capture_tls_client_hello --nocapture` will print the bytes.

---

## `bench_proxy` — integration benchmarks

Measures the **end-to-end latency** and **throughput** of a full proxy deployment:

```
reqwest (TLS) → proxy (TLS termination + fingerprinting) → Hyper backend (plain HTTP)
```

Everything runs in-process on localhost. No Docker, no external services.

### What is real

- TLS handshake (rcgen self-signed cert, reqwest/rustls client)
- JA4 fingerprinting (extracted from the actual TLS ClientHello bytes)
- Akamai fingerprinting (extracted from real HTTP/2 frames via `CapturingStream`)
- TCP networking (OS network stack, localhost)
- Backend: embedded Hyper HTTP/1.1 server

### What is simplified

- TCP SYN (eBPF) fingerprinting: **disabled** — requires `CAP_BPF` and kernel ≥ 5.11.
  Measure its overhead via Prometheus metrics in a staging environment instead.
- Backend always returns `200 OK "ok"` — we measure the proxy, not the backend.

### Benchmarks

| Name | Concurrency | Fingerprinting |
|---|---|---|
| `http1_latency/single_request_fingerprinting_on` | 1 | ON |
| `http2_latency/single_request_fingerprinting_on` | 1 | ON |
| `fingerprinting_overhead/http2_with_fingerprinting` | 1 | ON |
| `fingerprinting_overhead/http2_without_fingerprinting` | 1 | OFF |
| `concurrency_scaling/http1_concurrent_requests/1` | 1 | ON |
| `concurrency_scaling/http1_concurrent_requests/10` | 10 | ON |
| `concurrency_scaling/http1_concurrent_requests/50` | 50 | ON |

**Fingerprinting overhead** is the delta between `with_fingerprinting` and
`without_fingerprinting`. This is the real cost of JA4 + Akamai extraction per request.

**JA4 header assertion**: the HTTP/1.1 and HTTP/2 benchmarks assert that
`x-huginn-net-ja4` is present in every response. If it disappears (fingerprinting
regressed or the proxy changed), the bench panics immediately.

---

## Sustained load testing (external)

Criterion measures latency distributions under a single-client model.
For sustained multi-client load (RPS under production-like concurrency), use an
external tool against a running proxy instance:

```bash
# Start the proxy locally (TLS mode, all fingerprinting enabled)
cargo run -p huginn-proxy -- examples/compose.toml

# 30-second load test: 50 concurrent users, HTTP/1.1
oha --no-tls-verify -c 50 -z 30s https://127.0.0.1:7000/

# HTTP/2 load test
oha --no-tls-verify -c 50 -z 30s --http-version 2 https://127.0.0.1:7000/

# With hey (alternative)
hey -n 10000 -c 50 -disable-compression https://127.0.0.1:7000/
```

Key metrics to capture from `oha` output:
- p50 / p95 / p99 latency
- Requests/sec
- Error rate

---

## Interpreting results

Two fundamentally different latency modes are measured:

**Warm (connection reuse)** — `http1_latency`, `http2_latency`, `fingerprinting_overhead`:
A single client is built once and reuses its TLS connection across all iterations.
This models a keep-alive HTTP client hitting the proxy repeatedly.

**Cold (new TLS per request)** — `concurrency_scaling`:
Each concurrent request creates a new `reqwest::Client` (new TLS handshake).
This models N independent clients connecting simultaneously.

### Baseline numbers (localhost, release build)

| Benchmark | p50 |
|---|---|
| HTTP/1.1 single request (warm) | ~123 µs |
| HTTP/2 single request (warm) | ~124 µs |
| HTTP/2 with fingerprinting (warm) | ~121 µs |
| HTTP/2 without fingerprinting (warm) | ~102 µs |
| **Fingerprinting overhead (JA4 + Akamai)** | **~19 µs** |
| Cold request, c=1 (new TLS handshake) | ~39 ms |
| Cold throughput, c=10 | ~216 req/s |
| Cold throughput, c=50 | ~800 req/s |

Key observations:
- Fingerprinting overhead is **~19 µs** per request.
- HTTP/1.1 and HTTP/2 have equivalent warm latency; HTTP/2 does not add measurable overhead
  because the Akamai capture buffer is filled incrementally in the read path.
- Cold latency (~39 ms at c=1) is dominated by the TLS handshake, not the proxy logic.
  Throughput scales near-linearly with concurrency (c=50 → ~800 req/s).

If fingerprinting overhead grows significantly after a dependency update, suspect
`huginn-net-tls` or `huginn-net-http` parser changes — run `bench_fingerprinting`
to isolate which parser regressed.

---

## CI / regression detection

Benchmarks are not run in CI by default (they take ~3 minutes and need dedicated CPU).
To enable regression detection, run with a saved baseline and fail on > 10% regression:

```bash
cargo bench --bench bench_proxy -- --save-baseline main
# Later, on a PR branch:
cargo bench --bench bench_proxy -- --baseline main
```

Criterion exits with code 0 even when regressions are detected; post-process
`target/criterion/*/change/estimates.json` to enforce thresholds in CI.
