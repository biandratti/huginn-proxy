---
title: Benchmarks
description: Fingerprinting overhead and throughput figures.
sidebar:
  order: 11
---

Huginn Proxy is benchmarked with [Criterion](https://bheisler.github.io/criterion.rs/book/) (micro + integration) and external load tools (`oha`, `rewrk`, `k6`). Full methodology, fixtures, and raw numbers live in [`benches/`](https://github.com/biandratti/huginn-proxy/tree/master/benches) on GitHub.

## Environment

| | |
| --- | --- |
| **OS** | Linux |
| **CPU** | Intel Core i7-1165G7 @ 2.80 GHz (4 cores / 8 threads) |
| **Stack** | Single proxy + single eBPF agent + `traefik/whoami` backend (Docker Compose, localhost) |
| **Tool** | rewrk 0.3.2 · `c=512, t=4, 15 s` |

All figures are **indicative** (~±5–15 % between runs, more on HTTP/1.1; see note below). Criterion runs execute on the host without Compose; load tests target the Compose stack over localhost TLS, not a realistic network path.

## Fingerprinting overhead

Measured as the delta between `with_fingerprinting` and `without_fingerprinting` on a warm TLS connection (`cargo bench --bench bench_proxy`):

| Protocol | Overhead |
| --- | --- |
| HTTP/1.1 (JA4 only) | ~10 µs |
| HTTP/2 (JA4 + Akamai) | ~17 µs |

Pure parser cost (no network) is ~930–970 ns per fingerprint (`bench_fingerprinting`).

## Throughput: with eBPF vs without

The meaningful comparison is **with eBPF vs without eBPF**: it isolates the cost of TCP SYN fingerprinting on top of the TLS + HTTP fingerprinting baseline. All runs use HTTPS with TLS termination and full fingerprinting (the real production workload).

Averages over clean runs: **with eBPF n=5, without eBPF n=1** (the no-eBPF baseline has limited statistical weight).

| Config | Protocol | avg req/s | p50 | p95 | p99 |
| --- | --- | --- | --- | --- | --- |
| Without eBPF | HTTP/1.1 | ~25,200 | ~35 ms | ~100 ms | ~149 ms |
| Without eBPF | HTTP/2 | ~11,300 | ~47 ms | ~59 ms | ~75 ms |
| With eBPF | HTTP/1.1 | ~24,500 | ~38 ms | ~105 ms | ~154 ms |
| With eBPF | HTTP/2 | ~11,650 | ~45 ms | ~51 ms | ~59 ms |

**HTTP/1.1 req/s has high run-to-run variance** (~19k–34k depending on TLS connection-pool state). The averages are directionally correct but should not be read as stable figures. HTTP/2 multiplexes over fewer long-lived connections and is more stable (stdev < 3 % across all H2 runs).

**eBPF overhead: ~3 % on HTTP/1.1, negligible on HTTP/2.** The eBPF SYN map lookup cost per new connection is dominated by the TLS handshake at this concurrency.

These numbers are **not** a comparison with nginx, Envoy, or Caddy. Those benchmarks typically run plain HTTP without fingerprinting, which is not this proxy's use case. See the [benches README](https://github.com/biandratti/huginn-proxy/tree/master/benches) for full methodology, regression detection, and load test scripts.
