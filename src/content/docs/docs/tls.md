---
title: TLS
description: Certificates, ALPN, cipher suites, and mTLS. Beta.
sidebar:
  order: 5
---

The **`[tls]`** section configures **server-side TLS**: certificate paths, ALPN, optional file watch for cert reload, TLS version bounds, cipher suites, curves, and **mTLS** client certificate trust.

**Scope:** the proxy uses **one** certificate and key per process. **Per-SNI** (multiple certificates by server name) is **not** implemented. The feature is out of scope for this proxy, not a temporary gap.

## Minimal HTTPS

```toml
[tls]
cert_path = "/config/certs/server.crt"
key_path = "/config/certs/server.key"
alpn = ["h2", "http/1.1"]
watch_delay_secs = 60
```

## Options

Use **`[tls.options]`** (or equivalent nested tables in your schema) for:

- Allowed TLS versions (`1.2`, `1.3`)
- Cipher suites and **curve preferences**
- **`client_auth`:** CA paths for **mTLS** (global policy, not per-route)

## Example (cipher and curve lists)

See the [`examples/config/compose.toml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/config/compose.toml) file on GitHub for a full **`[tls.options]`** block with cipher suites and curves.

## Session resumption

TLS 1.2 session cache and TLS 1.3 session tickets can be tuned via **`[tls.session_resumption]`** (or the schema’s equivalent) where supported.

## Related

- [Security](/huginn-proxy/docs/security/): response headers (HSTS, CSP) and forwarding behavior
- [Configuration overview](/huginn-proxy/docs/configuration/): full top-level index
