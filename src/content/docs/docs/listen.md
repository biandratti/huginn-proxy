---
title: Listen
description: Bind addresses and TCP backlog. Beta.
sidebar:
  order: 2
---

The **`[listen]`** section controls where the proxy accepts client connections.

## Fields

- **`addrs`:** list of socket addresses (IPv4 and/or IPv6), for example `0.0.0.0:7000` and `[::]:7000` for dual-stack.
- **`tcp_backlog`:** listen queue depth (default is tuned for production-style workloads).

## Example

```toml
[listen]
addrs = ["0.0.0.0:7000", "[::]:7000"]
# tcp_backlog = 4096
```

See [Configuration overview](/huginn-proxy/docs/configuration/) for the full TOML layout.
