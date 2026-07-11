# Changelog

All notable changes to huginn-proxy are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning
follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

**Automatic TLS via ACME (TLS-ALPN-01)** (optional `acme` build feature)

A new `[acme]` block issues and renews certificates in-process via ACME (e.g. Let's Encrypt),
using the TLS-ALPN-01 challenge on `:443`. ACME lives in an isolated `huginn-acme` crate and is
wired in only when built with `--features acme`.

```toml
[acme]
contacts = ["ops@example.com"]                     # one or more account contacts
cache_dir = "/var/lib/huginn-proxy/acme"
# staging = true                                   # staging directory while testing
# directory_url = "https://acme.example.com/dir"   # private/test CA (e.g. Pebble)
# directory_ca_path = "/config/acme/ca.pem"        # trust a private CA (default: OS trust store)

[[domains]]
host = "api.example.com"
cert = { type = "acme" }     # omit `cert` entirely for ACME-by-default
```

- Directory TLS is validated against the **OS trust store** by default, so container images must
  ship a CA bundle (`ca-certificates`); `directory_ca_path` overrides it to trust a private or
  test ACME server such as [Pebble](https://github.com/letsencrypt/pebble).
- Cache files (account key and certs) are written `0600` inside `0700` directories, and write
  access is verified at startup (fail-fast) before any issuance begins.
- Readiness (`/ready`) waits for the first deployed certificate; renewal and error events are
  exported through `huginn_acme_*` metrics (see `TELEMETRY.md`), alongside a `huginn_acme_domains`
  gauge for the number of managed domains.
- Limitations: exact hosts only (no wildcards, use `cert = { type = "file" }` + cert-manager),
  single-replica cache, incompatible with global mTLS (`[tls.client_auth]`), and no EAB (CAs that
  require External Account Binding, e.g. ZeroSSL/Google Public CA, must use a file cert).
- The published `plain` and `ebpf` images now build with `acme` (inert until `[acme]` is set);
  `examples/docker-compose.acme.yml` is a self-contained demo that issues a real cert from Pebble.

**PROXY protocol support** (new `listen.proxy_protocol`: `off` / `optional` / `require`)

Recovers the real client IP/port from a PROXY v1 (text) or v2 (binary) header prepended by a
trusted L4 load balancer, honored only from peers in `security.trusted_proxies`. Affects eBPF SYN
lookup, `X-Forwarded-For`, rate limiting, and IP filtering. See `SETTINGS.md`.

**eBPF capture backend selection** (new `HUGINN_EBPF_CAPTURE` agent env var)

Values: `xdp-native` (default), `xdp-skb`, `tc`. XDP and TC programs ship in the same BPF object
with identical maps; no proxy config change required. See `EBPF-SETUP.md`.

### Breaking changes

**Domain certificate: three flat fields replaced by a single tagged `cert` field**

Each `[[domains]]` entry now declares its certificate source through one tagged `cert` table
instead of the flat `cert_path` / `key_path` / `acme` fields, making invalid combinations (ACME
together with file paths) unrepresentable.

```toml
# Before
cert_path = "/config/certs/api.crt"
key_path  = "/config/certs/api.key"

# After
cert = { type = "file", cert_path = "/config/certs/api.crt", key_path = "/config/certs/api.key" }
```

Omitting `cert` means plain HTTP (no `[tls]`), the default/catch-all certificate, or (when an
`[acme]` block is present) ACME-managed by default.

**`[tls.client_auth]`: enum replaced by an optional struct**

mTLS is now an optional block: present means required, omitted means disabled. The `disabled` and
`required = { ... }` wrapper forms are gone.

```toml
# Before
[tls.client_auth]
required = { ca_cert_path = "/config/certs/ca.crt" }

# After
[tls.client_auth]
ca_cert_path = "/config/certs/ca.crt"
# (omit the whole block to disable mTLS)
```

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
