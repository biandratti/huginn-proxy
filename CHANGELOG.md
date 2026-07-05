# Changelog

All notable changes to huginn-proxy are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning
follows [Semantic Versioning](https://semver.org/).

---

## [0.0.2-beta.2]

### Added

**Automatic TLS certificates via ACME (TLS-ALPN-01)** — optional `acme` build feature

A new `[acme]` block enables in-process certificate issuance and renewal through ACME
(e.g. Let's Encrypt), using the **TLS-ALPN-01** challenge on `:443`. ACME runs in an isolated
`huginn-acme` crate and is wired into the proxy only when built with `--features acme`.

```toml
[acme]
contacts = ["ops@example.com"]
cache_dir = "/var/lib/huginn-proxy/acme"
# staging = true            # use the staging directory while testing
# directory_url = "https://acme-v02.api.letsencrypt.org/directory"

[[domains]]
host = "api.example.com"
cert = { type = "acme" }     # or omit `cert` entirely → ACME-by-default
```

Notes / limitations: exact hosts only (no wildcards — use `cert = { type = "file" }` +
cert-manager), single-replica (the on-disk cache is not shared across replicas), incompatible
with global mTLS (`[tls.client_auth]`), and **no EAB** (External Account Binding — CAs that
require it, e.g. ZeroSSL/Google Public CA, must be used via a file cert). A new
`huginn_acme_domains` gauge reports the number of ACME-managed domains.

**Private/test ACME servers** — new optional `[acme].directory_ca_path`

Trusts a custom PEM CA for the ACME **directory** connection instead of the platform/OS trust
store, so the proxy can talk to a private or test ACME server (e.g.
[Pebble](https://github.com/letsencrypt/pebble)) served with a self-signed CA. The published
`plain` and `ebpf` images are now built with the `acme` feature (ACME stays inert until an
`[acme]` block is configured), and `examples/docker-compose.acme.yml` is a fully self-contained
local demo that issues a real cert from Pebble via TLS-ALPN-01.

### Breaking changes

**Domain certificate: `cert_path` / `key_path` / `acme` → a single `cert` field**

Each `[[domains]]` entry now declares its certificate source through one tagged `cert` table
instead of three flat fields. This makes invalid combinations (ACME together with file paths)
unrepresentable.

```toml
# Before (0.0.2-beta.0)
[[domains]]
host = "api.example.com"
cert_path = "/config/certs/api.crt"
key_path  = "/config/certs/api.key"

# After (0.0.2-beta.1)
[[domains]]
host = "api.example.com"
cert = { type = "file", cert_path = "/config/certs/api.crt", key_path = "/config/certs/api.key" }
```

Omitting `cert` means: plain HTTP (no `[tls]`), the default/catch-all certificate, or — when an
`[acme]` block is present — ACME-managed by default.

**`[tls.client_auth]`: enum → optional struct**

mTLS is now modeled as an optional block: present ⇒ required, omitted ⇒ disabled. The
`disabled` / `required = { … }` wrapper forms are gone.

```toml
# Before
[tls.client_auth]
required = { ca_cert_path = "/config/certs/ca.crt" }

# After
[tls.client_auth]
ca_cert_path = "/config/certs/ca.crt"
# (omit the whole block to disable mTLS)
```

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
