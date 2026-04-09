---
title: Backends
description: Upstream pool and HTTP version hints. Beta.
sidebar:
  order: 3
---

The top-level **`backends`** array defines upstream targets. Each route references a backend by its **`address`** string (must match exactly).

## Fields (per backend)

- **`address`:** `host:port` (or bracketed IPv6). In orchestrated setups this is usually a **service name** (Docker Compose, Kubernetes DNS, etc.).
- **`http_version`:** optional. Values: `http11`, `http2`, or negotiate with the upstream using **`preserve`** (default behavior depends on config schema).

## Example

```toml
backends = [
    { address = "backend-a:9000", http_version = "preserve" },
    { address = "backend-b:9000", http_version = "preserve" },
]
```

## Load balancing

Define one or more backends, then reference a backend address on each route. When a route lists **several** backend addresses, traffic is spread with **round-robin**. In practice, replicas and health are often handled **outside** the proxy (scheduler, Service endpoints).

**Scope:** In-proxy health probes, least-connections, and weighted routing are **not on the roadmap** for now. See [Routes](/huginn-proxy/docs/routes/) for prefix matching and [Configuration overview](/huginn-proxy/docs/configuration/) for the full file layout.
