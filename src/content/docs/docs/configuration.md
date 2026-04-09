---
title: Configuration overview
description: Single TOML file layout and links to each section. Beta.
sidebar:
  order: 1
---

Configuration is a **single TOML file** passed as the only CLI argument. There is **no hot reload** for the full config (TLS certificate files may reload when configured to watch them).

Use the pages below for field-level detail and examples.

## Top-level sections

| Section | Page |
| --- | --- |
| `[listen]` | [Listen](/huginn-proxy/docs/listen/) |
| `backends` | [Backends](/huginn-proxy/docs/backends/) |
| `routes` | [Routes](/huginn-proxy/docs/routes/) |
| `preserve_host` | Documented under [Routes](/huginn-proxy/docs/routes/) (behavior when forwarding upstream) |
| `[tls]` | [TLS](/huginn-proxy/docs/tls/) |
| `[fingerprint]` | [Fingerprinting](/huginn-proxy/docs/fingerprinting/) |
| `[security]` | [Security](/huginn-proxy/docs/security/) (IP filter, connection cap, response security headers). **[Rate limiting](/huginn-proxy/docs/rate-limiting/)** is configured under `[security.rate_limit]` and per-route overrides. |
| `[timeout]` | Connect, idle, shutdown, TLS handshake, connection handling, HTTP/1.1 keep-alive (HTTP/2 uses persistent connections). |
| `[logging]` | Log level and format. |
| `[telemetry]` | [Telemetry](/huginn-proxy/docs/telemetry/) |
| `[headers]` | [Headers](/huginn-proxy/docs/headers/): global request/response add/remove |

## CLI

```bash
huginn-proxy /path/to/config.toml
```

## Related

- [How it works](/huginn-proxy/docs/how-it-works/): request path through the proxy
- [Quick example](/huginn-proxy/docs/quick-example/): minimal TOML
