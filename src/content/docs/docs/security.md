---
title: Security
description: IP ACL, rate limiting, TLS, and security headers. Beta.
sidebar:
  order: 11
---

The **`[security]`** block groups controls that apply **before** and **around** request handling: who may connect (IP ACL), how fast they may send traffic (token-bucket rate limits), what response headers to add (HSTS, CSP, custom), and connection limits. **TLS** (server certificates, cipher policy, optional **mTLS**) is configured under **`[tls]`** and is documented separately from the ACL/rate/header knobs. Separately, the proxy sets trusted **`X-Forwarded-*`** headers for backends so downstream services see a consistent client identity and scheme—without trusting spoofed client values.

Each section below gives the idea first, then **TOML snippets** you can copy or adapt.

## IP filtering

`[security.ip_filter]` supports **allowlist** or **denylist** mode with IPv4/IPv6 **CIDR** entries. Empty allowlist denies all; empty denylist allows all (per the configured mode).

There is **no** GeoIP or ASN filtering in the proxy itself.

**Disabled (default in the compose example):**

```toml
[security.ip_filter]
mode = "disabled"
```

**Allowlist — only these networks can reach the proxy:**

```toml
[security.ip_filter]
mode = "allowlist"
allowlist = [
  "127.0.0.1/32",
  "::1/128",
  "10.0.0.0/8",
]
```

**Denylist — block specific ranges:**

```toml
[security.ip_filter]
mode = "denylist"
denylist = ["198.51.100.0/24"]
```

## Rate limiting

Token-bucket **global** limits live under `[security.rate_limit]`. **Per-route** limits use `[routes.rate_limit]` on each `[[routes]]` entry (see the rate-limit example file for full `[[routes]]` layout).

Key strategies include limiting by:

- Client IP (`limit_by = "ip"`)
- Named request header (`limit_by = "header"` + `limit_by_header`)
- Route identity (`limit_by = "route"`)
- Combined IP + route (`limit_by = "combined"`)

Responses use **429** when exceeded. Counters are **in-memory** and **per process**; they are **not** shared across replicas—plan limits per instance or use an external gate if you need cluster-wide quotas.

**Global default (excerpt):**

```toml
[security.rate_limit]
enabled = true
requests_per_second = 1000
burst = 2000
window_seconds = 1
limit_by = "ip"
```

**Per-route override** (after a `[[routes]]` block in the same file; see the example repo for ordering):

```toml
[routes.rate_limit]
enabled = true
requests_per_second = 50
burst = 100
limit_by = "combined"
```

## Security headers

HSTS, CSP, X-Frame-Options, and custom headers can be attached to **responses** globally under `[security.headers]`. There is **no** per-route security header block in this beta.

**Example —** matches the style in [`compose.toml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/config/compose.toml):

```toml
[security.headers]
custom = [
  { name = "X-Frame-Options", value = "DENY" },
  { name = "X-Content-Type-Options", value = "nosniff" },
]

[security.headers.hsts]
enabled = true
max_age = 31536000
include_subdomains = false
preload = false

[security.headers.csp]
enabled = true
policy = "default-src 'self'; script-src 'self' 'unsafe-inline'"
```

## TLS and mTLS

Server-side TLS terminates at the proxy with configurable protocols and cipher policies. **mTLS** can require client certificates signed by a configured CA; this is a **global** policy (not per-route). See [Configuration reference](/huginn-proxy/docs/configuration/) for `client_auth` and `[tls.options]` fields.

**Minimal TLS server (excerpt):**

```toml
[tls]
cert_path = "/config/certs/server.crt"
key_path = "/config/certs/server.key"
alpn = ["h2", "http/1.1"]
```

## Forwarding headers

The proxy sets trusted **`X-Forwarded-*`** values for backends:

- **`X-Forwarded-For`:** appends the client IP to any existing value (comma-separated), or creates the header.
- **`X-Forwarded-Host`:** set from the **TLS SNI** when present; client-supplied values are **not** trusted and are removed first.
- **`X-Forwarded-Port` / `X-Forwarded-Proto`:** derived from the peer connection and scheme.

You do not need to configure these in TOML for standard behavior. Global **[`headers`](/huginn-proxy/docs/configuration/)** `request` add/remove lists are separate from forwarding.
