---
title: Security
description: IP ACL, rate limiting, TLS, and security headers. Beta.
sidebar:
  order: 11
---

## IP filtering

`[security.ip_filter]` supports **allowlist** or **denylist** mode with IPv4/IPv6 **CIDR** entries. Empty allowlist denies all; empty denylist allows all (per the configured mode).

There is **no** GeoIP or ASN filtering in the proxy itself.

## Rate limiting

Token-bucket **global** limits live under `[security.rate_limit]`. **Per-route** limits live under `[routes.rate_limit]` on a route.

Key strategies include limiting by:

- Client IP
- Named request header
- Route identity
- Combined strategies

Responses use **429** when exceeded. Counters are **in-memory** and **per process**; not distributed across replicas.

## Security headers

HSTS, CSP, X-Frame-Options, and custom headers can be attached to **responses** globally. There is **no** per-route security header block in this beta.

## TLS and mTLS

Server-side TLS terminates at the proxy with configurable protocols and cipher policies. **mTLS** can require client certificates signed by a configured CA; this is a **global** policy (not per-route). See [Configuration reference](/huginn-proxy/docs/configuration/) for `client_auth` fields.

## Forwarding headers

`X-Forwarded-For`, `Host`, `X-Forwarded-Proto`, and related fields are set by the proxy and **override** client-supplied values to prevent spoofing.
