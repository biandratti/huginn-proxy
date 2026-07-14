# Changelog

All notable changes to huginn-proxy are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning
follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

**PROXY protocol support (`listen.proxy_protocol`)**

New static option `listen.proxy_protocol.mode` (`off` / `optional` / `require`) plus
`listen.proxy_protocol.header_timeout_ms` (default `100`). Recovers the real client IP/port from a
PROXY v1 (text) or v2 (binary) header prepended by a trusted L4 load balancer. Honored only from
peers listed in `security.trusted_proxies`. Affects eBPF SYN lookup, `X-Forwarded-For`, rate
limiting, and IP filtering. See `SETTINGS.md`.

**eBPF capture backend selection (`HUGINN_EBPF_CAPTURE`)**

New agent env var. Values: `xdp-native` (default), `xdp-skb`, `tc`. Both XDP and TC programs
ship in the same BPF object and share identical maps; no proxy config change required.
See `EBPF-SETUP.md`.

**Effective configuration output**

New `--print-effective-config` CLI flag validates the config and prints deterministic,
secret-redacted JSON with applied defaults, normalizations, and fallbacks, then exits. Proxy
startup now logs a safe aggregate summary at `info` and the complete redacted view at `debug`.

### Changed

- Configuration loading now rejects unknown or misplaced keys at every nesting level during
  startup, `--validate`, and hot reload.

---

## [0.0.2-beta.1]

### Breaking changes

**`[[routes]]` replaced by `[[domains]]` / `[[domains.routes]]`**

Top-level `[[routes]]` blocks no longer exist. Routes are now nested inside domain entries:

```toml
# Before (v0.0.1-beta.7)
[[routes]]
prefix = "/api"
backend = "backend-a:9000"

# After (0.0.2-beta.0)
[[domains]]
host = "api.example.com"
cert_path = "/config/certs/api.crt"
key_path  = "/config/certs/api.key"

  [[domains.routes]]
  prefix  = "/api"
  backend = "backend-a:9000"
```

A **catch-all** domain (matches any host, plain HTTP) uses a host-less entry:

```toml
# Before
[[routes]]
prefix  = "/"
backend = "localhost:3000"

# After
[[domains]]          # no host = catch-all

  [[domains.routes]]
  prefix  = "/"
  backend = "localhost:3000"
```

**`[tls]` no longer carries `cert_path` / `key_path`**

Certificate paths moved to each `[[domains]]` entry. The `[tls]` section now only
contains transport options (`alpn`, `[tls.options]`):

```toml
# Before
[tls]
cert_path = "/config/certs/server.crt"
key_path  = "/config/certs/server.key"
alpn      = ["h2", "http/1.1"]

# After
[tls]
alpn = ["h2", "http/1.1"]   # cert/key moved to [[domains]]
```

**`trusted_proxies` moved from `[security.rate_limit]` to `[security]`**

It is now a global, non-overridable setting:

```toml
# Before
[security.rate_limit]
trusted_proxies = ["10.0.0.0/8"]

# After
[security]
trusted_proxies = ["10.0.0.0/8"]   # removed from rate_limit block
```

### Added

- **Domain-based routing** (`[[domains]]`) — groups TLS certificate, headers, security
  policy, and routes under one hostname (exact or `*.wildcard`). Host matching is
  authority-first (`:authority` / `Host` header), not SNI. Catch-all domain (no `host`)
  mirrors a Traefik router with no `Host()` rule.
- **`sni_strict`** option in `[tls.options]` — rejects connections with no SNI or
  unmatched SNI (parity with Traefik's `sniStrict: true`).
- **Automatic 421 Misdirected Request** for coalesced HTTP/2 connections where the
  request host is served by a different certificate than the SNI-selected one.
- **`[security].trusted_proxies`** — global CIDR list for real-client-IP resolution
  from `X-Forwarded-For`; consumed by rate limiting (`limit_by = "ip" | "combined"`).
- **Per-domain security overrides** — `[domains.security]` and
  `[domains.routes.security]` accept `ip_filter`, `rate_limit`, and `security.headers`
  as **whole-block replacements** (not field-level merges).
- **`fingerprinting` on `[[domains]]`** — domain-level gate that combines with the
  per-route toggle: `route.or(domain).unwrap_or(true)`.
- **Readiness probe decoupled from backends** — `/ready` now returns 200 once the proxy
  listeners are accepting connections, independent of backend availability (backends down
  → 502 + metrics, not a readiness failure). Matches Traefik/Envoy semantics.
- **`min_version` / `max_version`** keys in `[tls.options]` — parsed and validated
  (currently not enforced by the TLS stack; see note in SETTINGS.md).
- **Multi-DNS / multiple listen addresses** support.
- **Graceful shutdown** — readiness fails first on SIGTERM so orchestrators drain traffic
  before the process stops accepting connections.

### Changed

- `preserve_host` documented as **Dynamic** (hot-reloadable).
- `http_version` default clarified: `preserve` for HTTPS clients, `http11` for plain
  HTTP (was documented as `null (preserve)`).
- `health_check = {}` (empty table) enables a **TCP probe** with default thresholds —
  it does *not* mean "off". Omit the key entirely to leave the backend unprobed.
- Omitting all backends is now explicitly valid: requests return **421** (no domain
  match), **404** (domain matched, no route), or **502** (route matched, no healthy
  backend).
- Rate-limit scope description updated: per-domain and per-route overrides are
  whole-block replaces, not field merges.
- Fingerprint header names renamed from `x-huginn-net-*` to protocol-scoped names
  (`x-tls-ja4*`, `x-http2-akamai`, `x-tcp-p0f`).

---

[0.0.2-beta.0]: https://github.com/biandratti/huginn-proxy/compare/v0.0.1-beta.7...0.0.2-beta.0
