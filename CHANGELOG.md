# Changelog

All notable changes to huginn-proxy are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning
follows [Semantic Versioning](https://semver.org/).

---

## [0.0.5-beta.0]

### Added

- **Two-phase graceful shutdown.** On SIGTERM, `/ready` fails first (`proxy_draining`) while the traffic port still accepts for `timeout.drain_delay_secs` (default `0`). Then accept stops and in-flight connections drain for `shutdown_secs`. `/live` stays 200. See `DEPLOYMENT.md`.
- **Health body format.** `telemetry.health_format` (`json` default, or `text`) on `/health`, `/ready`, `/live`. Agent: `HUGINN_EBPF_HEALTH_FORMAT`. See `TELEMETRY.md`.
- **Hitless eBPF attach + capture gate.** Agent pins the capture `bpf_link` (TCX / XDP fd-link) so a restart can replace the program without detaching. Proxy `/ready` ANDs a capture gate (`capture_absent` / `capture_draining` / `capture_detached`; text `NOCAPTURE`) when TCP SYN fingerprinting is on. Roll the agent image first, then the proxy. A rollout still blips `/ready` even where the pinned link keeps capturing. See `EBPF-SETUP.md`.

### Breaking changes

- **`/ready` 200 JSON is now `{"status":"serving"}`** (was `ready`). Text token is `SERVING`.

### Changed

- **TLS accept noise is `debug`.** Routine client noise (peer abort, unmatched SNI, non-TLS bytes) no longer logs at `warn`; timeouts and cert/mTLS failures stay `warn`. `huginn_tls_handshake_errors_total` is unchanged; `huginn-net-tls` JA4 parse logs above `debug` are suppressed.
- **`/ready` 503 now reports why:** `proxy_starting` or `proxy_draining` (text: `STARTING` / `DRAINING`). With TCP fingerprinting, also `capture_*` (text: `NOCAPTURE`). The observability server stays up until after drain.
- **Agent `/ready`** is attached + required pins + not draining (not pins-only). kubelet only; do not AND it with the proxy as a second load-balancer monitor.

---

## [0.0.4-beta.0]

### Added

- **Client-CA dedup by Subject Key Identifier.** Repeated CAs in a `client_ca_path` bundle collapse to one anchor; CAs without SKID fall back to DER identity.
- **mTLS context in TLS failure logs.** `TLS accept failed` / `handshake timeout` warnings now include `sni` and `mtls`.
- **Config validation warnings + `--validate --strict`.** Non-fatal audits on boot, validate, and hot reload; `--strict` fails on warnings. See `SETTINGS.md`.
- **In-kernel per-source SYN rate limiter (eBPF).** Optional Count-Min Sketch limiter via `HUGINN_EBPF_RATE_LIMIT_*` env vars; skips fingerprint capture above threshold, packet still forwarded. See `EBPF-SETUP.md` and `TELEMETRY.md`.

### Breaking changes

- **`[security].trusted_proxies` is now a table** (`cidrs` + `insecure`). `insecure = true` replaces listing `0.0.0.0/0`.

  ```toml
  [security.trusted_proxies]
  cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
  insecure = false
  ```

- **Filesystem watch moved to `[reload]`.** `--watch`/`--watch-delay-secs` flags and `HUGINN_WATCH`/`HUGINN_WATCH_DELAY_SECS` removed; defaults to `watch = true`.

  ```toml
  [reload]
  watch = true
  debounce_secs = 60
  ```

- **`[tls.client_auth]` removed; mTLS is per-domain via `client_ca_path`.** Configs with `[tls.client_auth]` are rejected at load.

  ```toml
  # before
  [tls.client_auth]
  required = { ca_cert_path = "/config/certs/ca.crt" }

  # after
  [[domains]]
  host = "admin.example.com"
  cert_path = "/config/certs/admin.crt"
  key_path = "/config/certs/admin.key"
  client_ca_path = "/config/certs/ca.crt"
  ```

- **`[tls.session_resumption].max_sessions` removed.** Stateless tickets only; key is rejected if present.

### Changed

- **TLS version limits are now enforced** (`min_version`/`max_version`/`versions`).
- **`curve_preferences` is now applied** (was validated then ignored). Empty default keeps PQ-first provider defaults; explicit classical-only lists drop PQ unless you include `X25519MLKEM768` or `SECP256R1MLKEM768`. `secp521r1` removed.
- **TLS resumption is stateless tickets only** (shared ticketer, TLS 1.3 resumption enabled; mTLS domains never resume).
- **`huginn_config_hash` / `huginn_tls_cert_hash` use fixed FNV-1a** — values change once on upgrade; comparable across replicas thereafter.

### Fixed

- **`huginn_errors_total` double-counted handler rejections** — adjust alert thresholds (~half rate for `ip_blocked`, `misdirected_request`, `no_matching_route`). `TELEMETRY.md` corrected.
- **Multi-key PEM files now pick the matching key** instead of always using the last one.

---

## [0.0.3-beta.0]

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
Sensitive values (custom header values, CSP policy) are wrapped in an internal secret type that
serializes as `<redacted>` by construction, so they can never leak through the effective-config
view or logs regardless of how the config grows.

### Changed

- Configuration loading now rejects unknown or misplaced keys at every nesting level during
  startup, `--validate`, and hot reload.

### Fixed

- eBPF SYN map handling now survives agent restarts: the agent reuses pinned maps when
  possible, and the proxy reconnects if map IDs change (e.g. after
  `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` changes).

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
