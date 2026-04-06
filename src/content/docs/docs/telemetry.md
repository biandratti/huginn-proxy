---
title: Telemetry
description: Metrics, health endpoints, and scraping. Beta.
sidebar:
  order: 20
---

When `telemetry.metrics_port` is set, Huginn Proxy serves observability on **that port only**, separate from the main proxy listener.

## Endpoints

| Path | Role |
| --- | --- |
| `/health` | Process is running |
| `/ready` | Ready to serve (503 when not ready, e.g. no backends) |
| `/live` | Liveness probe |
| `/metrics` | Prometheus text exposition |

Responses are JSON for health endpoints; `/metrics` is Prometheus text.

## Prometheus

Scrape `http://<host>:<metrics_port>/metrics`. Example `scrape_configs` target: `localhost:9090`.

## Metric families (overview)

Counters and histograms cover, among others:

- **Connections:** totals, active, rejections
- **Requests:** counts and latency histograms
- **Throughput:** bytes to/from clients and backends (label caveats apply for chunked bodies)
- **TLS:** handshakes, durations, errors, session-related gauges
- **Fingerprints:** JA4 and HTTP/2 extraction success/failure and timings; TCP SYN map hit/miss/malformed when eBPF is enabled
- **Backends:** selections, errors, durations
- **Rate limit:** evaluated / allowed / rejected
- **IP filter:** evaluated / allowed / denied
- **Headers:** added / removed counts
- **mTLS:** connections with client certificates
- **Build info:** version metadata

## eBPF agent

The sidecar agent exposes the **same four HTTP paths** for Kubernetes-style probes, plus agent-specific counters (SYN capture, insert failures, malformed records). Configure bind address and port with `HUGINN_EBPF_METRICS_ADDR` and `HUGINN_EBPF_METRICS_PORT`.
