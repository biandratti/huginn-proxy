---
title: Configuration reference
description: TOML layout for Huginn Proxy. Beta.
sidebar:
  order: 10
---

Configuration is a **single TOML file** passed as the only CLI argument. There is no hot reload for the full config (TLS certificates may reload when configured to watch files).

## Top-level sections

| Section | Purpose |
| --- | --- |
| `listen` | Bind addresses, TCP backlog |
| `backends` | Upstream pool (HTTP version hint per backend) |
| `routes` | Prefix → backend, fingerprint toggle, rewrites, per-route rate limits |
| `preserve_host` | Whether to forward the original `Host` header |
| `tls` | Certificates, ALPN, cipher suites, mTLS client auth, session resumption |
| `fingerprint` | Enable TLS / HTTP/2 / TCP SYN fingerprint extraction |
| `logging` | Log level and format |
| `timeout` | Connect, idle, shutdown, TLS handshake, connection handling, keep-alive |
| `security` | Global connection cap, IP filter, global rate limit, security headers |
| `telemetry` | Metrics and health port |
| `headers` | Global request/response header add/remove |

## Listen

- `addrs`: list of socket addresses (IPv4 and/or IPv6).
- `tcp_backlog`: listen queue depth (default is high for production-style workloads).

## Backends

Each `[[backends]]` entry has an `address` and optional `http_version` (`http11`, `http2`, or preserve negotiation).

## Routes

Each `[[routes]]` entry includes:

- `prefix`: path prefix to match
- `backend`: must match a configured backend address
- `fingerprinting`: enable or disable TLS + HTTP/2 fingerprint headers for this route
- `force_new_connection`: bypass backend connection pooling when `true`
- `replace_path`: strip / rewrite options (see [Routing](routing/))
- Optional nested `[routes.rate_limit]` and `[routes.headers]`

## TLS (`[tls]`)

Server certificate and key paths, ALPN list, optional file watch interval, TLS version bounds, cipher suites, curves, and client certificate trust for **mTLS**. Session resumption can be tuned (TLS 1.2 cache size, etc.).

**Limitations:** one certificate material per process in typical setups; no per-SNI multi-cert vhost story in this beta.

## Fingerprint (`[fingerprint]`)

- `tls_enabled`, `http_enabled`, `tcp_enabled`: toggles
- `max_capture`: cap for HTTP/2 capture buffer (default in the tens of KiB range)

TCP SYN requires `ebpf-tcp` at build time and the agent. See [eBPF TCP setup](ebpf-setup/).

## Timeouts (`[timeout]`)

Separate knobs for connect, idle, graceful shutdown, TLS handshake, overall connection handling, and HTTP/1.1 keep-alive. HTTP/2 uses persistent connections; keep-alive does not apply the same way.

## Telemetry (`[telemetry]`)

`metrics_port` enables a **separate** HTTP server for `/health`, `/ready`, `/live`, and `/metrics`. See [Telemetry](telemetry/).

## Headers (`[headers]`)

Optional global `request` / `response` add and remove lists. Distinct from per-route header rules under `[[routes]]`.
