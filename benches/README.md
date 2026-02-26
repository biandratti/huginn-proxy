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

**TLS ClientHello** (`benches/fixtures/clienthello_reqwest.bin`): real bytes intercepted from
a `reqwest`/`rustls` connection before the TLS handshake. Committed to the repo so benchmarks
are deterministic without an active network connection.

**HTTP/2 frames** (`HTTP2_CLIENT_FRAMES` in `bench_fingerprinting.rs`): hardcoded bytes
encoding the connection preface, SETTINGS frame, and WINDOW_UPDATE frame that `reqwest`/`h2`
sends at connection start. Values are derived from the Akamai fingerprint captured by
`capture_fixtures`.

#### Refreshing fixtures after a dependency update

```bash
cargo test -p huginn-proxy-lib --test capture_fixtures -- --nocapture
```

This re-captures real bytes from a live `reqwest` connection and writes:
- `benches/fixtures/clienthello_reqwest.bin` — new TLS ClientHello bytes
- `benches/fixtures/fingerprint_values.txt` — new `EXPECTED_JA4` / `EXPECTED_AKAMAI` strings

Update the `EXPECTED_*` constants in `bench_fingerprinting.rs` and `bench_proxy.rs` to match.

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

| Name | Protocol | Concurrency | Fingerprinting |
|---|---|---|---|
| `http1_latency/single_request_fingerprinting_on` | HTTP/1.1 | 1 | ON |
| `http2_latency/single_request_fingerprinting_on` | HTTP/2 | 1 | ON |
| `fingerprinting_overhead/http1_with_fingerprinting` | HTTP/1.1 | 1 | ON |
| `fingerprinting_overhead/http1_without_fingerprinting` | HTTP/1.1 | 1 | OFF |
| `fingerprinting_overhead/http2_with_fingerprinting` | HTTP/2 | 1 | ON |
| `fingerprinting_overhead/http2_without_fingerprinting` | HTTP/2 | 1 | OFF |
| `concurrency_scaling/http1_c/10` | HTTP/1.1 | 10 | ON |
| `concurrency_scaling/http1_c/50` | HTTP/1.1 | 50 | ON |
| `concurrency_scaling/http2_c/10` | HTTP/2 | 10 | ON |
| `concurrency_scaling/http2_c/50` | HTTP/2 | 50 | ON |

**Fingerprinting overhead** is the delta between `with_fingerprinting` and
`without_fingerprinting` for each protocol. The H1 delta isolates JA4 cost;
the H2 delta isolates JA4 + Akamai cost together.

**Fingerprint value assertion**: every fingerprinted request asserts that
`x-huginn-net-ja4` (and `x-huginn-net-akamai` for HTTP/2) matches the values
captured in `benches/fixtures/fingerprint_values.txt`. If either changes after a
dependency update, the bench panics with a message pointing to `capture_fixtures`.

---

## Sustained load testing (external)

Criterion measures latency distributions under a single-client model.
For sustained multi-client load (RPS under production-like concurrency), use an
external tool against a running proxy instance:

```bash
# Start the proxy locally (TLS mode, all fingerprinting enabled)
cargo run -p huginn-proxy -- examples/compose.toml

# 30-second load test: 50 concurrent users, HTTP/1.1
oha --insecure -c 50 -z 30s https://127.0.0.1:7000/

# HTTP/2 load test
oha --insecure -c 50 -z 30s --http-version 2 https://127.0.0.1:7000/
```

### Load test results (oha, c=50, 30s, localhost)

| Protocol | req/s | p50 | p95 | p99 | p99.9 |
|---|---|---|---|---|---|
| HTTP/1.1 | ~15,400 | 2.9 ms | 6.3 ms | 9.9 ms | 24.3 ms |
| HTTP/2   | ~9,200  | 1.1 ms | 42 ms  | 44 ms  | 57 ms  |

Two 30-second runs, fingerprinting enabled, backend returns `"ok"` instantly (same machine).
The ~39–50 "errors" are connections aborted by `oha` at the 30-second deadline — not proxy errors.

**HTTP/1.1** shows a clean unimodal distribution. The vast majority of requests complete under
11 ms; the tail is occasional connection setup, not proxy jitter.

**HTTP/2** shows a bimodal distribution: p50 ≈ 1.1 ms (multiplexing reuses open connections),
but ~10% of requests spike to ~42–48 ms. Those spikes are new TLS handshakes — `oha` opens
fresh H2 connections as the pool saturates, each costing ~40–50 ms. The bimodal shape is a
load-tool artifact, not a proxy behavior. Real H2 clients (browsers, gRPC stubs) that maintain
persistent connections would stay in the sub-ms range for the hot path.

**Production capacity note:** the 15,400 req/s figure assumes a zero-latency backend and is a
proxy overhead ceiling, not a production target. In practice, throughput is gated by backend
latency. With 50 keep-alive connections the rule of thumb is `50 × (1000 / backend_ms)` req/s.
A 10 ms backend → ~4,500 req/s; a 50 ms backend → ~900 req/s. The proxy overhead (~0.08 ms)
is negligible in both cases. What this test does confirm is that the proxy handles sustained
load without errors and without measurable per-request degradation over time.

---

## Interpreting results

Two fundamentally different latency modes are measured:

**Warm (connection reuse)** — `http1_latency`, `http2_latency`, `fingerprinting_overhead`:
A single client is built once and reuses its TLS connection across all iterations.
This models a keep-alive HTTP client hitting the proxy repeatedly.

**Cold (new TLS per request)** — `concurrency_scaling`:
Each concurrent request creates a new `reqwest::Client` (new TLS handshake).
This models N independent clients connecting simultaneously.

### Environment

Measured on an Intel Core i7-1165G7 (4 cores, 2.80 GHz) with 32 GB RAM, localhost,
release build. Results may vary ±5–10% depending on CPU thermal state.

### Baseline numbers (localhost, release build)

| Benchmark | p50 |
|---|---|
| HTTP/1.1 single request (warm) | ~79 µs |
| HTTP/2 single request (warm) | ~85 µs |
| HTTP/1.1 with fingerprinting (warm) | ~77 µs |
| HTTP/1.1 without fingerprinting (warm) | ~74 µs |
| **Fingerprinting overhead H1 (JA4 only)** | **~2.5 µs** |
| HTTP/2 with fingerprinting (warm) | ~79 µs |
| HTTP/2 without fingerprinting (warm) | ~75 µs |
| **Fingerprinting overhead H2 (JA4 + Akamai)** | **~3.6 µs** |
| Cold throughput, c=10, H1 | ~221 req/s |
| Cold throughput, c=10, H2 | ~217 req/s |
| Cold throughput, c=50, H1 | ~804 req/s |
| Cold throughput, c=50, H2 | ~818 req/s |

Key observations:
- Fingerprinting overhead is **~2.5 µs** (H1, JA4 only) and **~3.6 µs** (H2, JA4 + Akamai).
  The extra ~1 µs on H2 is the cost of Akamai SETTINGS/WINDOW_UPDATE parsing.
- HTTP/1.1 and HTTP/2 have near-identical warm latency; H2 frame processing does not add
  measurable overhead because the Akamai capture buffer is filled incrementally in the read path.
- Cold throughput is dominated by TLS handshake cost. H1 and H2 scale equivalently:
  c=10 → ~219 req/s, c=50 → ~811 req/s.

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
