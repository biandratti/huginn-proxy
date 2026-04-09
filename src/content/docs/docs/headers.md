---
title: Headers
description: Global request and response header add/remove. Beta.
sidebar:
  order: 10
---

The **`[headers]`** section configures **global** request and response header manipulation. It is distinct from:

- **Per-route** header rules under routes (see your schema’s `[[routes]]` / route tables)
- **`[security.headers]`:** HSTS, CSP, and custom **security** response headers (see [Security](/huginn-proxy/docs/security/))
- **Forwarding:** `X-Forwarded-*` set by the proxy (see [Security](/huginn-proxy/docs/security/#forwarding-headers))

## Structure

Typically:

- **`[headers.request]`:** `add` / `remove` lists
- **`[headers.response]`:** `add` / `remove` lists

## Example

```toml
[headers.request]
remove = ["X-Forwarded-Server"]
add = [
    { name = "X-Proxy-Name", value = "huginn-proxy" },
]

[headers.response]
remove = ["Server", "X-Powered-By"]
add = [
    { name = "X-Proxy", value = "huginn-proxy" },
]
```

See [`examples/config/compose.toml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/config/compose.toml) on GitHub for a complete example.

## Related

- [Configuration overview](/huginn-proxy/docs/configuration/)
