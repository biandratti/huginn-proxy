---
title: Rate limiting
description: Token-bucket limits globally and per route. Beta.
sidebar:
  order: 8
---

Token-bucket **global** limits live under **`[security.rate_limit]`**. **Per-route** limits use **`[routes.rate_limit]`** on each `[[routes]]` entry (see [`examples/config/rate-limit-example.toml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/config/rate-limit-example.toml) on GitHub for a full file).

## Strategies

Key **`limit_by`** values:

- **`ip`:** client IP
- **`header`:** value of a named header (`limit_by_header`)
- **`route`:** shared limit per route path
- **`combined`:** IP + route

Responses use **429** when exceeded. Counters are **in-memory** and **per process**; they are **not** shared across replicas.

## Global default

```toml
[security.rate_limit]
enabled = true
requests_per_second = 1000
burst = 2000
window_seconds = 1
limit_by = "ip"
```

## Per-route override

After a `[[routes]]` block in the same file (ordering matters in TOML):

```toml
[routes.rate_limit]
enabled = true
requests_per_second = 50
burst = 100
limit_by = "combined"
```

## Related

- [Security](/huginn-proxy/docs/security/): IP filter and security headers
- [Routes](/huginn-proxy/docs/routes/): prefix and backend selection
- [Configuration overview](/huginn-proxy/docs/configuration/)
