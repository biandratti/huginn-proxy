---
title: Routing
description: Prefix routes, strip and rewrite, load balancing. Beta.
sidebar:
  order: 5
---

## Prefix matching

Routes are matched by **URL prefix**. **First match wins:** declare more specific prefixes before general ones.

## Path manipulation

Per route you can:

- Forward the path unchanged
- **Strip** the matched prefix so the backend sees a shorter path
- **Rewrite** the prefix to a different prefix (query strings are preserved)

There is **no regular-expression** routing, only prefix matching.

## Backends and balancing

Define one or more `[[backends]]` entries, then reference a backend address on each route. Multiple backends are selected with **round-robin** load balancing.

**Limitations (beta):** no built-in health checks; unhealthy backends are not automatically removed. No least-connections or weighted algorithms.

## Connection reuse

HTTP/1.1 and HTTP/2 reuse connections to backends where possible. Use `force_new_connection = true` on a route when you need a fresh connection (for example, fingerprinting scenarios that require new TLS handshakes).

See [Configuration reference](configuration/) for the exact TOML fields.
