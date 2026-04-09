---
title: Routing
description: Prefix routes, strip and rewrite, load balancing. Beta.
sidebar:
  order: 5
---

## Prefix matching

Routes are matched by **URL prefix**. **First match wins:** declare more specific prefixes before general ones (for example `/api` and `/api/v2` before `/`).

**Example — order matters:**

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
- **Rewrite** the prefix to a different prefix (`replace_path = "/new/...`) — query strings are preserved

There is **no regular-expression** routing, only prefix matching.

**Strip —** request `/strip/users` → backend receives `/users`:

```toml
routes = [
    { prefix = "/strip", backend = "backend-a:9000", replace_path = "" },
]
```

**Rewrite —** request `/old/data` → backend receives `/new/data`:

```toml
routes = [
    { prefix = "/old", backend = "backend-b:9000", replace_path = "/new" },
]
```

**Rewrite to a versioned API —** request `/v1/endpoint` → backend receives `/api/v1/endpoint`:

```toml
routes = [
    { prefix = "/v1", backend = "backend-a:9000", replace_path = "/api/v1" },
]
```

## Backends and balancing

Declare backends in the top-level `backends` array, then reference each backend `address` on routes.

```toml
backends = [
    { address = "backend-a:9000", http_version = "preserve" },
    { address = "backend-b:9000", http_version = "preserve" },
]

routes = [
    { prefix = "/api", backend = "backend-a:9000" },
    { prefix = "/", backend = "backend-b:9000" },
]
```

Define one or more backends, then reference a backend address on each route. In this first phase, the design is **orchestrator-first**: backends are usually **stable service names** from Kubernetes Services, Nomad, etc. (`backend-a:9000`, `api.default.svc.cluster.local`), not a standalone appliance-style load balancer. When a route lists **several** backend addresses, traffic is spread with **round-robin**; replicas and health are often handled **outside** the proxy (scheduler, Service endpoints, sidecars).

**Scope:** Built-in backend health probes, automatic removal of failed upstreams, least-connections, and weighted routing are **not on the roadmap** right now—they are out of scope for this phase, not a “beta” feature waiting to ship. The proxy assumes **orchestrated** deployments (or an **external** load balancer) own endpoint health and replicas. If you run **without** an orchestrator, handle upstream health and failover outside Huginn Proxy.

## Connection reuse

HTTP/1.1 and HTTP/2 reuse **connections to backends** where possible (connection pooling). `force_new_connection = true` bypasses that pool and opens a **new TCP connection to the upstream** for each request (and a new TLS session if the backend speaks TLS). That is **only** about the proxy→backend leg.

It does **not** change whether client fingerprints are available: TLS JA4 and HTTP/2 signatures come from the client→proxy connection; TCP SYN (`x-huginn-net-tcp`) is captured on the client→proxy path via eBPF and is unrelated to backend pooling. Forcing new backend connections does **not** re-capture the client’s SYN.

```toml
routes = [
    # New upstream TCP (and TLS if applicable) per request — e.g. backends that bind state to a connection
    { prefix = "/isolated", backend = "backend-a:9000", force_new_connection = true },
    { prefix = "/api", backend = "backend-a:9000", force_new_connection = false },
]
```

`force_new_connection = true` adds latency; use it only when you need per-request upstream connections.

See [Configuration reference](/huginn-proxy/docs/configuration/) for all route and backend fields.
