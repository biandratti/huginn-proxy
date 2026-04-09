---
title: Security
description: IP ACL, connection limits, response security headers, and trusted forwarding. Beta.
sidebar:
  order: 7
---

The **`[security]`** block groups controls that apply **before** and **around** request handling: who may connect (IP ACL), how fast they may send traffic (see [Rate limiting](/huginn-proxy/docs/rate-limiting/) for `[security.rate_limit]`), connection caps, and **response** security headers (HSTS, CSP, custom).

**TLS** termination and **mTLS** are configured under **`[tls]`**; see [TLS](/huginn-proxy/docs/tls/).

Separately, the proxy sets trusted **`X-Forwarded-*`** headers for backends so downstream services see a consistent client identity and scheme, without trusting spoofed client values.

Each section below gives the idea first, then **TOML snippets** you can copy or adapt.

## IP filtering

`[security.ip_filter]` supports **allowlist** or **denylist** mode with IPv4/IPv6 **CIDR** entries. Empty allowlist denies all; empty denylist allows all (per the configured mode).

There is **no** GeoIP or ASN filtering in the proxy itself.

**Disabled (default in the compose example):**

```toml
[security.ip_filter]
mode = "disabled"
```

**Allowlist (only these networks can reach the proxy):**

```toml
[security.ip_filter]
mode = "allowlist"
allowlist = [
  "127.0.0.1/32",
  "::1/128",
  "10.0.0.0/8",
]
```

**Denylist (block specific ranges):**

```toml
[security.ip_filter]
mode = "denylist"
denylist = ["198.51.100.0/24"]
```

## Security headers

HSTS, CSP, X-Frame-Options, and custom headers can be attached to **responses** globally under `[security.headers]`. There is **no** per-route security header block in this beta.

**Example:** matches the style in [`compose.toml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/config/compose.toml):

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

## Forwarding headers

The proxy sets trusted **`X-Forwarded-*`** values for backends:

- **`X-Forwarded-For`:** appends the client IP to any existing value (comma-separated), or creates the header.
- **`X-Forwarded-Host`:** set from the **TLS SNI** when present; client-supplied values are **not** trusted and are removed first.
- **`X-Forwarded-Port` / `X-Forwarded-Proto`:** derived from the peer connection and scheme.

You do not need to configure these in TOML for standard behavior. Global **[Headers](/huginn-proxy/docs/headers/)** `request` add/remove lists are separate from forwarding.

## Related

- [Rate limiting](/huginn-proxy/docs/rate-limiting/) — `[security.rate_limit]` and per-route overrides
- [TLS](/huginn-proxy/docs/tls/) — certificates and mTLS
- [Configuration overview](/huginn-proxy/docs/configuration/)
