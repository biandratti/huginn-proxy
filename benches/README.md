# Huginn Proxy - Benchmarks

This document collects **Criterion** runs (micro + integration), optional **external** load tests (`oha`, `k6` with fingerprint checks), and notes on reading CPU/memory from Docker. All published figures are **indicative**: they track regressions and capacity **for this proxy and feature set** (TLS + fingerprinting, etc.) on a **specific machine**. They are **not** a substitute for a fair shootout against nginx, Envoy, or Caddy unless workload, TLS settings, and functionality are aligned — those tools optimize for different defaults and rarely include the same fingerprinting path.

Two benchmark suites with different scopes:

| Suite | File | Scope |
|---|---|---|
| `bench_fingerprinting` | `benches/bench_fingerprinting.rs` | Micro - pure parsing, no network |
| `bench_proxy` | `benches/bench_proxy.rs` | Integration - full proxy round-trip |

## Environment

**Load tests** (oha, k6) target a **minimal Docker Compose** stack: **one** proxy, **one** eBPF agent, and **one** backend — a simplified layout on purpose; **more replicas and stronger hardware** usually improve throughput and latency. **Criterion** runs (`cargo bench`, release) execute on the host without Compose. All figures are **indicative** (~**±5–15%** between runs).

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

## `bench_fingerprinting` - micro benchmarks

Benchmarks the raw parsing speed of each fingerprinting algorithm.
No network, no IO - pure CPU work on hardcoded byte fixtures.

### Benchmarks

| Name | What it measures |
|---|---|
| `akamai_parse_http2_preface_settings_window_headers` | `extract_akamai_fingerprint_from_bytes()` on preface + SETTINGS + WINDOW_UPDATE + HEADERS (HPACK pseudo-headers, same tail as `fingerprint_values.txt`) |
| `ja4_parse_tls_client_hello` | `parse_tls_client_hello()` on a TLS 1.3 ClientHello |

### Sample numbers (`cargo bench --bench bench_fingerprinting`)

Criterion **estimate** (middle value). Three consecutive runs; table uses the **last** run. See **Environment** at the top of this document.

| Benchmark | Estimate |
|---|---|
| `akamai_parse_http2_preface_settings_window_headers` | ~970 ns |
| `ja4_parse_tls_client_hello` | ~930 ns |

### Fixtures

**TLS ClientHello** (`benches/fixtures/clienthello_reqwest.bin`): real bytes intercepted from
a `reqwest`/`rustls` connection before the TLS handshake. Committed to the repo so benchmarks
are deterministic without an active network connection.

**HTTP/2 frames** (`HTTP2_CLIENT_FRAMES` in `bench_fingerprinting.rs`): hardcoded bytes for
preface, SETTINGS, WINDOW_UPDATE, plus a minimal HEADERS(stream 1) block so the Akamai string
matches `fingerprint_values.txt` (HPACK indices match `hpack_patched`’s static table, not the full RFC appendix).

#### Refreshing fixtures after a dependency update

```bash
cargo test -p huginn-proxy-lib --test capture_fixtures -- --nocapture
```

This re-captures real bytes from a live `reqwest` connection and writes:
- `benches/fixtures/clienthello_reqwest.bin` - new TLS ClientHello bytes
- `benches/fixtures/fingerprint_values.txt` - new `EXPECTED_JA4` / `EXPECTED_AKAMAI` strings

Update the `EXPECTED_*` constants in `bench_fingerprinting.rs` and `bench_proxy.rs` to match.

---

## `bench_proxy` - integration benchmarks

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

- TCP SYN (eBPF) fingerprinting: **disabled** - requires `CAP_BPF` and kernel ≥ 5.11.
  Measure its overhead via Prometheus metrics in a staging environment instead.
- Backend always returns `200 OK "ok"` - we measure the proxy, not the backend.

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
docker compose -f examples/docker-compose.release-ebpf.yml up --build

# 30-second load test: 50 concurrent users, HTTP/1.1
oha --insecure -c 50 -z 30s https://127.0.0.1:7000/

# HTTP/2 load test
oha --insecure -c 50 -z 30s --http-version 2 https://127.0.0.1:7000/
```

### Load test results (oha, c=50, 30s, localhost)

Medians over **three** runs per protocol (same host, Compose TLS proxy, example backend ~800 B/response).

| Protocol | req/s | p50 | p95 | p99 | p99.9 |
|---|---|---|---|---|---|
| HTTP/1.1 | ~12,700 | 3.2 ms | 7.2 ms | 16.6 ms | 46.9 ms |
| HTTP/2   | ~7,200  | 0.86 ms | 42 ms | 44 ms | 50 ms |

Success rate 100%; “aborted due to deadline” at end of window is an `oha` artifact, not proxy failure.

**HTTP/1.1** — mostly unimodal; one run reached ~17.5k req/s, the other two ~12.4–12.7k (table uses medians). Typical p50 in the **low ms** range for this setup.

**HTTP/2** — bimodal: p50 **sub‑ms** on the fast path, but p90+ dominated by **~42–44 ms** spikes (new TLS/H2 connections as `oha` spins connections). Compare H1 vs H2 **req/s** on equal `-c`/`-z`: H2 completes fewer requests in the same wall clock with this client.

**Production capacity note:** the ~12.7k req/s H1 figure is **not** a universal ceiling — it depends on backend, payload, and hardware. Rule of thumb with 50 concurrent clients: `50 × (1000 / backend_ms)` req/s when backend latency dominates. What these runs show is sustained load **without HTTP errors**; tail latencies must be read in context (tooling + TLS churn).

---

## Interpreting results

Two fundamentally different latency modes are measured:

**Warm (connection reuse)** - `http1_latency`, `http2_latency`, `fingerprinting_overhead`:
A single client is built once and reuses its TLS connection across all iterations.
This models a keep-alive HTTP client hitting the proxy repeatedly.

**Cold (new TLS per request)** - `concurrency_scaling`:
Each concurrent request creates a new `reqwest::Client` (new TLS handshake).
This models N independent clients connecting simultaneously.

### Baseline numbers (localhost, `cargo bench --bench bench_proxy`)

Medians from Criterion’s **estimate** line (middle value). Refreshed after **three** consecutive runs; the table below matches the **last** run when the baseline comparison was stable. Same **Environment** as at the top of this document.

| Benchmark | Estimate |
|---|---|
| HTTP/1.1 single request (warm) | ~172 µs |
| HTTP/2 single request (warm) | ~182 µs |
| HTTP/1.1 with fingerprinting (warm) | ~174 µs |
| HTTP/1.1 without fingerprinting (warm) | ~166 µs |
| **Fingerprinting overhead H1 (JA4 only)** | **~10 µs** |
| HTTP/2 with fingerprinting (warm) | ~181 µs |
| HTTP/2 without fingerprinting (warm) | ~162 µs |
| **Fingerprinting overhead H2 (JA4 + Akamai)** | **~17 µs** |
| Cold throughput, c=10, H1 | ~221 req/s |
| Cold throughput, c=10, H2 | ~221 req/s |
| Cold throughput, c=50, H1 | ~1000 req/s |
| Cold throughput, c=50, H2 | ~1000 req/s |

Key observations:
- Integration **round-trip** is **~170–185 µs** warm (TLS + localhost + Hyper), not sub‑100 µs.
  Sub‑microsecond **parser-only** cost is what `bench_fingerprinting` measures; the delta here is **tens of µs** and mixes TLS + scheduling noise.
- Fingerprinting overhead (with vs without) is **~10 µs** on H1 and **~17 µs** on H2 in this snapshot — use as a trend, not an absolute (runs vary ±5–15%).
- Cold throughput is dominated by TLS handshakes; c=50 lands near **~1000** completed requests/s per benchmark design.

If fingerprinting overhead grows significantly after a dependency update, suspect
`huginn-net-tls` or `huginn-net-http` parser changes — run `bench_fingerprinting`
to isolate parser cost.

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

---

## Load with k6

Use the same TLS stack as the sustained-load examples: bring up the proxy (and eBPF agent) with Compose, then run k6 from the **repository root**. The URL is **`https://`**: traffic is still **TLS-encrypted**. **`--insecure-skip-tls-verify`** only disables **certificate chain / hostname verification** against the system trust store (needed for the usual self-signed dev certs). It does **not** turn off TLS — same role as `curl -k` or `oha --insecure`. Drop the flag when using a CA-trusted certificate.

The script **checks** that fingerprint headers (JA4, Akamai, TCP SYN) appear in the **backend echo** (header echo from `traefik/whoami`), not on the response seen by the k6 client.

```bash
docker compose -f examples/docker-compose.release-ebpf.yml up --build

k6 run --insecure-skip-tls-verify benches/load/k6/fingerprints.js
```

All fingerprint checks are **on by default**. Disable individual checks with env vars:

| Variable | Default | Description |
|---|---|---|
| `NO_CHECK_JA4=true` | off | Skip JA4 TLS fingerprint checks (`ja4`, `ja4_r`, `ja4_o`, `ja4_or`) |
| `NO_CHECK_AKAMAI=true` | off | Skip Akamai HTTP/2 fingerprint check (auto-skipped when `K6_NO_HTTP2=true`) |
| `NO_CHECK_TCP_SYN=true` | off | Skip TCP SYN fingerprint check — use when running without the eBPF agent |
| `K6_CHECKS_RATE` | `0.99` | Minimum required check success rate (e.g. `0.995`) |
| `K6_FAILED_RATE` | `0` (steady) / `0.02` (ramp) | Maximum tolerated HTTP error rate |

> **RAMP mode thresholds:** `RAMP=true` drives the proxy to saturation by design — some errors
> at the 300 VU stage are expected. The script uses `rate<=0.02` (≤ 2 % errors) in ramp mode
> instead of the strict `rate==0` used in steady-state runs. Override with `--env K6_FAILED_RATE=0.01`.

#### OS tuning for high-VU tests

When TCP SYN checks are active (`noConnectionReuse: true`), every request opens a fresh TCP
connection consuming one ephemeral port. The kernel keeps closed ports in `TIME_WAIT` for
`tcp_fin_timeout` seconds. At high VU counts this can exhaust the ephemeral port range before
the proxy becomes the bottleneck.

| Scenario | Required conn/s | Recommended tuning |
|---|---|---|
| ≤ 30 VUs + TCP SYN | < 470 | none (default `tcp_fin_timeout=60`, 28k ports) |
| 50 VUs + TCP SYN | ~700 | `sudo sysctl -w net.ipv4.tcp_fin_timeout=15` |
| RAMP to 300 VUs | ~2 000 peak | `tcp_fin_timeout=10` + `ip_local_port_range="10000 65535"` |
| Any VU count, no TCP SYN | n/a | no tuning needed — keep-alive reuses connections |

Both settings are **temporary** and revert on reboot.

Examples:

```bash
# Default: 5 VUs / 30s with all fingerprint checks
k6 run --insecure-skip-tls-verify benches/load/k6/fingerprints.js

# Higher steady load — tune TIME_WAIT first (see table above)
k6 run --env VUS=50 --env DURATION=60s --insecure-skip-tls-verify benches/load/k6/fingerprints.js

# Ramp to saturation: 10 → 50 → 150 → 300 VUs (~4 min)
# Tune OS first: sudo sysctl -w net.ipv4.tcp_fin_timeout=10 net.ipv4.ip_local_port_range="10000 65535"
# Expects ≤ 2% errors at the 300 VU peak (proxy saturation point).
k6 run --env RAMP=true --insecure-skip-tls-verify benches/load/k6/fingerprints.js

# HTTP/1.1 only (Akamai auto-skipped)
k6 run --env K6_NO_HTTP2=true --insecure-skip-tls-verify benches/load/k6/fingerprints.js

# Without eBPF agent — re-enables keep-alive for maximum throughput
k6 run --env NO_CHECK_TCP_SYN=true --insecure-skip-tls-verify benches/load/k6/fingerprints.js

# Pure throughput (no fingerprint checks, keep-alive, 50 VUs)
k6 run --env VUS=50 --env DURATION=60s --env NO_CHECK_TCP_SYN=true \
  --insecure-skip-tls-verify benches/load/k6/fingerprints.js
```

### CPU / memory (container)

k6 doesn’t show cgroup usage — use `docker stats` on the `proxy` container while the test runs. App counters: `http://127.0.0.1:9090/metrics`.