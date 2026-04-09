---
title: Routes
description: Prefix matching, path strip/rewrite, and backend connection reuse. Beta.
sidebar:
  order: 4
---

Each route maps a **URL prefix** to a **backend** `address` (defined under [`backends`](/huginn-proxy/docs/backends/)). Optional fields control fingerprint headers, rate limits, path rewrites, and connection pooling.

## Prefix matching

Routes are matched by **URL prefix**. **First match wins:** declare more specific prefixes before general ones (for example `/api` and `/api/v2` before `/`).

**Example (order matters):**

```toml
routes = [
    { prefix = "/api/v2", backend = "backend-a:9000" },
    { prefix = "/api", backend = "backend-b:9000" },
    { prefix = "/", backend = "backend-b:9000" },
]
```

A request to `/api/v2/health` matches `/api/v2`, not `/api`.

## Path manipulation

Per route you can:

- Forward the path unchanged (omit `replace_path` or leave default behavior)
- **Strip** the matched prefix so the backend sees a shorter path (`replace_path = ""`)
- **Rewrite** the prefix to a different prefix (`replace_path = "/new/...`). Query strings are preserved.

There is **no regular-expression** routing, only prefix matching.

**Strip:** request `/strip/users` → backend receives `/users`:

```toml
routes = [
    { prefix = "/strip", backend = "backend-a:9000", replace_path = "" },
]
```

**Rewrite:** request `/old/data` → backend receives `/new/data`:

```toml
routes = [
    { prefix = "/old", backend = "backend-b:9000", replace_path = "/new" },
]
```

**Rewrite to a versioned API:** request `/v1/endpoint` → backend receives `/api/v1/endpoint`:

```toml
routes = [
    { prefix = "/v1", backend = "backend-a:9000", replace_path = "/api/v1" },
]
```

## Route fields (summary)

- **`prefix`**, **`backend`**, **`fingerprinting`**, **`force_new_connection`**, **`replace_path`**
- Optional **`[routes.rate_limit]`:** see [Rate limiting](/huginn-proxy/docs/rate-limiting/)
- Optional per-route header rules: see [Headers](/huginn-proxy/docs/headers/) and the configuration schema

**`preserve_host`** (top-level): when `true`, the original client `Host` header can be forwarded upstream; see [Configuration overview](/huginn-proxy/docs/configuration/).

## Connection reuse

HTTP/1.1 and HTTP/2 reuse **connections to backends** where possible (connection pooling). `force_new_connection = true` bypasses that pool and opens a **new TCP connection to the upstream** for each request (and a new TLS session if the backend speaks TLS). That is **only** about the proxy→backend leg.

It does **not** change whether client fingerprints are available: TLS JA4 and HTTP/2 signatures come from the client→proxy connection; TCP SYN (`x-huginn-net-tcp`) is captured on the client→proxy path via eBPF and is unrelated to backend pooling. Forcing new backend connections does **not** re-capture the client’s SYN.

```toml
routes = [
    { prefix = "/isolated", backend = "backend-a:9000", force_new_connection = true },
    { prefix = "/api", backend = "backend-a:9000", force_new_connection = false },
]
```

`force_new_connection = true` adds latency; use it only when you need per-request upstream connections.

See [Configuration overview](/huginn-proxy/docs/configuration/) for the full TOML layout.
