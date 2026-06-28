# Features

Huginn Proxy is a reverse proxy focused on passive fingerprinting. The main goal is to extract TLS and HTTP/2
fingerprints from client connections and forward them to backend services for analysis and bot detection.

Security features like TLS termination, mTLS, rate limiting, and IP filtering are included to meet production
requirements. But this is not a general-purpose reverse proxy trying to compete with Nginx or HAProxy. Some common
features you might expect are missing because they don't align with the fingerprinting use case.

If you need advanced load balancing algorithms, or complex routing rules, you should use a different proxy. This one
does fingerprinting well and includes enough infrastructure features to run in production, but nothing more.

## Protocol Support

**HTTP/1.1 and HTTP/2**

Both protocols are fully supported. HTTP/2 multiplexing works as expected. The proxy automatically handles protocol
negotiation via ALPN when TLS is enabled.

Limitation: HTTP/3 is not supported yet.

**IPv4 and IPv6**

The proxy listens on both IPv4 and IPv6 simultaneously. Configure multiple `listen.addrs` entries (e.g.,
`"0.0.0.0:7000"` for IPv4 and `"[::]:7000"` for IPv6). Backend addresses, IP filtering rules, and all observability
endpoints support both address families.

## Load Balancing

**Round-robin algorithm**

Basic round-robin distribution across multiple backends. Works well for most use cases where backends have similar
capacity.

Limitation: no least-connections, no weighted or priority policies beyond this simple round-robin (when load balancing
is in use for multiple upstreams).

**Backend health checks (active probes)**

Optional per-backend `health_check` in the config: **TCP** connect, or **HTTP** `GET` to a path (plain `http://` to the
backend address, same as normal forwarding). Consecutive-failure thresholds with hysteresis: when a backend is marked
unhealthy, the proxy answers with **502** for matching routes instead of waiting on TCP connect timeouts.

Recommended usage: this is most useful when Huginn Proxy is the main resiliency layer (VM/bare-metal/Docker Compose, or
direct upstream addresses). In orchestrators (for example Kubernetes `Service`), proxy health checks are optional: they
can overlap with readiness filtering, but can still be valuable for faster failover at the proxy, stricter app-level
checks, or extra protection during rollout/transient endpoint lag.

Limitation: the HTTP probe does not use TLS to the upstream (use a **TCP** check, or an HTTP path that responds over
cleartext on the same `host:port` you already use for backend traffic).

## Path-based Routing

**Prefix matching with path manipulation**

Routes are matched by URL prefix. You can strip the prefix, replace it with a different path, or leave it unchanged. The
**most specific (longest) prefix wins** — routes are sorted by prefix length at config load time, so declaration order
does not affect which route matches.

Examples: `/api/v2` beats `/api` beats `/` for a request to `/api/v2/users`. `/api` can be forwarded as-is, stripped to
`/`, or rewritten to `/v1`. Query parameters are preserved.

Declaration order only matters for routes with identical prefixes, which are treated as load-balance candidates for
round-robin selection (multi-upstream groups).

Limitation: No regex support. Only simple prefix matching.

## Multi-Domain Routing

**Virtual hosting with per-domain certificates and routes**

Routes are grouped under `[[domains]]` entries. Each domain owns a `host` pattern, an optional TLS certificate
(`cert_path` / `key_path`), optional domain-scoped `headers`, and its own set of `routes`. A request is first matched to
a domain by host, then to a route by prefix within that domain.

Host matching order is **exact host → single-label wildcard (`*.example.com`) → catch-all**. The catch-all is the entry
with no `host` field (at most one is allowed); it matches any host not claimed by an exact or wildcard entry, including
IP literals and `localhost`. A request whose host matches no domain is answered with **421 Misdirected Request**.

The routing host is resolved from the HTTP-layer authority, uniformly for HTTP/1.1 and HTTP/2 (like nginx, Traefik, and
Envoy): the request URI authority first (`:authority` pseudo-header in HTTP/2, or absolute-form request target in
HTTP/1.1), then the `Host` header as fallback. TLS SNI is **not** a routing input — it only selects the certificate at
the TLS layer and drives the optional `sni_strict` handshake rejection. Cert selection (SNI) and routing (HTTP host) are
reconciled by the always-on **421 Misdirected Request** check on coalesced connections. Host comparison is
case-insensitive and IPv6 brackets are stripped before matching (`[::1]` matches a domain configured as `::1`).

`cert_path` and `key_path` are optional but must be supplied together — omit both for a plain-HTTP domain. Specifying
only one is a validation error. Duplicate hosts and more than one catch-all are also rejected at config load.

Limitation: Wildcard is one label deep only. Routing is host + path prefix; no header- or method-based routing.

## Rate Limiting

**Fixed-window counter (per process)**

Configurable at three scopes — **global** (`[security.rate_limit]`), **per-domain**
(`[domains.security.rate_limit]`), and **per-route** (`[domains.routes.security.rate_limit]`). Security policy lives
under `security` at every scope, so the path is consistent. You can limit by IP, custom header, route path, or a
combination. The effective limit is **`burst` requests per `window_seconds`** window, tracked with `pingora_limits`'
atomic rate counter. (`requests_per_second` is currently not used for enforcement — the cap is `burst` over the
window; size `burst`/`window_seconds` to the rate you want.)

For `limit_by = "ip"` / `"combined"`, the client IP is resolved from the global
[`[security].trusted_proxies`](SETTINGS.md#top-level-security-keys) (walking `X-Forwarded-For`); without it the
non-forgeable TCP peer IP is used.

Precedence is **global → domain → route**, **whole-block replace** at every scope: a domain's `rate_limit` block fully
replaces the global policy for that domain, and a route's block fully replaces the domain-effective policy for that
route
(not a field-level merge — re-state every key you want to keep; e.g. a route block without `enabled = true` disables the
limit for that route). Limiters are keyed per domain, so the same route prefix under two domains is tracked
independently.

Tracks limits in-memory, so restarting the proxy resets all counters.

Limitation: No distributed rate limiting across multiple proxy instances. Limits are per-process only.

## Security Headers

**HSTS, CSP, and custom headers**

HSTS is configurable with max-age, includeSubdomains, and preload directives. CSP policies are customizable. Any custom
header can be added to all responses. Security headers can be set globally (`[security.headers]`), **per-domain**
(`[domains.security.headers]`), or **per-route** (`[domains.routes.security.headers]`); the most specific scope that
sets
the block replaces the parent's entirely (whole-block, not merged — a scope that sets only CSP does not inherit the
parent's HSTS).

Header manipulation (add/remove on both request and response) can be configured at three scopes: **global**,
**per-domain** (`[domains.headers]`), and **per-route** (`[domains.routes.headers]`). They are applied in the order
**global → domain → route**, with the most specific scope winning when the same header name is set at multiple levels.
Within each scope, removals are applied before additions.

Limitation: No header-value templating; values are static strings.

## IP Filtering

**ACL with allowlist/denylist**

Supports CIDR notation for both IPv4 and IPv6. You pick either allowlist mode (only these IPs) or denylist mode (block
these IPs). Empty allowlist blocks everything, empty denylist allows everything.

Configurable globally (`[security.ip_filter]`), **per-domain** (`[domains.security.ip_filter]`), or **per-route**
(`[domains.routes.security.ip_filter]`); the most specific scope that sets a filter replaces the parent's entirely.
When **no route in the matched domain** sets its own `ip_filter`, the domain/global filter runs after host/domain
resolution but before route selection, so a blocked client never learns whether a route exists. When **any route in the
domain** sets an `ip_filter`, the check for that whole domain defers to after route match (router-level ACL, like
Traefik) and uses the matched route's resolved filter (`route.or(domain).or(global)`).

Limitation: No geographic filtering or ASN-based rules.

## TLS Termination

**Server-side TLS with hot reload**

Configurable cipher suites, curve preferences, and TLS version restrictions (1.2 and 1.3 supported). ALPN works for
HTTP/2 negotiation.

**SNI-based multi-certificate selection.** The proxy serves a different certificate per domain, selected from the TLS
ClientHello SNI. Each `[[domains]]` entry declares its certificate source via a single `cert` field (`cert = { type = "file", cert_path = "…", key_path = "…" }`, or `cert = { type = "acme" }`). The resolver picks a certificate by
**exact host → single-label wildcard (`*.example.com`) → default**. The default certificate is the one attached to the
catch-all (host-less) domain, and it is also served to clients that send no SNI (e.g. connecting by IP). When
`[tls.options].sni_strict = true`, the default-cert fallback is disabled entirely (full parity with Traefik's
`sniStrict`): both an SNI hostname that matches no configured domain **and** a connection that sends no SNI are
rejected with `unrecognized_name` — IP-literal HTTPS clients no longer get the default cert in this mode. Default is
`sni_strict = false`, where both cases fall back to the default cert. See the **Multi-Domain Routing** section below for
how domains tie certificates to routes.

**Misdirected-request enforcement (HTTP 421, always on).** Routing follows the request `:authority` / `Host`, not SNI,
so
a reused (coalesced) HTTP/2 connection could carry a request for a host served by a different certificate. Huginn
rejects
that with `421 Misdirected Request` — the same default protection nginx and Apache `mod_http2` apply (RFC 9110
§15.5.20 /
RFC 7540 §9.1.2). Because huginn uses a single global TLS configuration, "authoritative" reduces to "served by the same
certificate": a request whose host is not covered by the certificate the connection's SNI selected is rejected. The
check
compares certificate coverage rather than literal `authority == SNI`, so hosts sharing a single certificate (a
`*.example.com`
wildcard, or distinct domains pointing at the same SAN cert file) still coalesce. It is not configurable — it only fires
on
genuinely cross-certificate requests, and plain HTTP / no-SNI connections are unaffected.

Certificates are re-read as part of a **config reload** — driven by SIGHUP or by a change to the *config file* (when the
`--watch` file watcher is enabled, debounced by a configurable delay), not by an independent cert-file watcher. Each
reload re-reads the cert/key files from their configured paths. The `DynamicCertResolver` is updated in place and its
cert map is swapped atomically (`ArcSwap`); the acceptor's `ServerConfig` itself is built once at startup, so cipher
suites, ALPN, client auth, and session resumption settings never drift between the initial configuration and reloaded
certificates.

Reloading is **best-effort and per-domain** (Traefik-style): if one domain's new certificate fails to load, the other
domains still swap to their fresh certs, and the failing domain keeps serving its previously loaded certificate so a
transient file issue never drops TLS for that domain.

Each successful load or rotation increments `huginn_tls_cert_reload_total{result="success", domain="…"}`, updates
`huginn_tls_cert_last_reload_timestamp_seconds{domain="…"}`, and publishes the new certificate-chain content hash via
`huginn_tls_cert_hash{domain="…"}` — all labeled per domain.
Failed rebuilds bump the `result="error"` counter but leave the hash and timestamp gauges untouched, so dashboards
always reflect the last *good* certificate actually serving traffic. See [TELEMETRY.md](TELEMETRY.md) §13 for the full
metric reference and example alert queries.

**Cipher suite selection.** Suites are read from `[tls.options].cipher_suites` in the config file and applied as the
exact set offered to clients. Names are validated at startup against the suites supported by the underlying TLS provider
(`aws-lc-rs`); an unknown or misspelled suite fails the boot with an explicit error listing the supported names — there
is no silent fallback. When `cipher_suites` is empty or omitted, the proxy uses the safe defaults provided by
`aws-lc-rs`.

Limitation: Wildcard matching is single-label only (`*.example.com` matches `api.example.com` but not
`a.b.example.com`). The cipher suite list is global — the same set is offered for every domain, since SNI selects the
certificate but not the TLS parameters.

**Automatic TLS (ACME / Let's Encrypt).** When an `[acme]` block is configured, domains that do not declare an explicit
`cert = { type = "file" }` obtain and renew their certificate automatically via the **TLS-ALPN-01** challenge — there is
no separate `cert = { type = "acme" }` needed (omitting `cert` under a global `[acme]` is ACME-by-default). Validation
happens on the **same TLS listener** (the proxy answers the `acme-tls/1` ALPN challenge in-band), so the public
**`:443`** just needs to be reachable; no `:80` listener and no DNS provider credentials are required. Issued certs are
cached on disk (`[acme].cache_dir`) and survive restarts. A custom directory CA can be trusted via
`[acme].directory_ca_path` for private/test ACME servers (e.g. Pebble). The `acme` cargo feature is **compiled into the
published `plain` and `ebpf` images** and stays completely inert unless `[acme]` is present. See
[SETTINGS.md](SETTINGS.md) for configuration and [DEPLOYMENT.md](DEPLOYMENT.md) for operational guidance.

ACME limitations: **TLS-ALPN-01 only** (no HTTP-01, no DNS-01), so **no wildcards** — a wildcard domain must use
`cert = { type = "file" }` (e.g. fed by cert-manager); **single-replica** (the on-disk cache is not shared, so N
replicas issue N certs and may hit CA rate limits); **incompatible with global mTLS** (`[tls.client_auth]`), rejected at
config validation; and **no EAB** (External Account Binding — CAs that require it, e.g. ZeroSSL / Google Public CA, must
be used via a file cert).

## TLS Session Resumption

**TLS 1.2 session IDs and TLS 1.3 session tickets**

Session resumption reduces handshake overhead for subsequent connections. TLS 1.2 uses server-side session ID caching (
default: 256 sessions), while TLS 1.3 uses stateless session tickets.

Enabled by default. Configurable via `session_resumption.enabled` and `session_resumption.max_sessions` (for TLS 1.2
cache size).

Limitation: TLS 1.3 ticket lifetime and rotation are managed by rustls defaults. No manual control over ticket
encryption keys or expiration.

## mTLS (Mutual TLS)

**Client certificate authentication**

When enabled, clients must present a valid certificate signed by the configured CA. Supports multiple CA certificates in
a single file.

This is a global setting. Either all routes require client certs, or none do.

Limitation: No per-route mTLS configuration. No option for optional client certificates (it's either required or
disabled).

## Fingerprinting

**TLS (JA4), HTTP/2 (Akamai), and TCP SYN (p0f-style)**

Passive fingerprinting extracts three types of signatures from client connections:

- **TLS (JA4)** - extracted from the TLS ClientHello. Injected as `x-tls-ja4` (sorted, hashed),
  `x-tls-ja4-r` (sorted, raw), `x-tls-ja4-o` (original order, hashed), `x-tls-ja4-or` (original
  order, raw), `x-tls-ja4-s1` (sorted, ephemeral extensions excluded, hashed), `x-tls-ja4-s1r`
  (sorted, ephemeral extensions excluded, raw).
- **HTTP/2 (Akamai)** - extracted from HTTP/2 SETTINGS and WINDOW_UPDATE frames. Injected as `x-http2-akamai`.
- **TCP SYN (p0f)** - extracted from the raw TCP SYN packet via an eBPF/XDP program attached to the network
  interface. Injected as `x-tcp-p0f`. Requires the `ebpf-tcp` build feature and `tcp_enabled = true` in config.

Per-domain and per-route control to enable/disable TLS and HTTP/2 fingerprint **header injection**
(`route.or(domain).unwrap_or(true)`; a route overrides its domain). Whether the signatures are *captured* at all is the
static global `[fingerprint]` config. TCP SYN fingerprinting is global (controlled by the `fingerprint.tcp_enabled`
flag).

The TCP SYN signature follows the p0f format: `ip_ver:ttl:ip_olen:mss:wsize,wscale:olayout:quirks:pclass`. Quirks
extracted include IP-level flags (DF, ECN, reserved bit, IP ID anomalies) and TCP-level flags (zero-seq, non-zero ACK,
URG/PUSH flags, excessive window scale, timestamps).

**TCP SYN fingerprinting limitations:**

- **Linux only** - eBPF/XDP does not run on macOS or Windows. Requires kernel ≥ 5.11.
- Present on all requests of a connection (including HTTP keep-alive), since the fingerprint describes the TCP
  connection, not individual requests.

Limitation: Fingerprints are only extracted and forwarded, not validated or used for blocking. Backend services need to
handle the actual fingerprint analysis and decision making.

## Connection Pooling

**HTTP/1.1 and HTTP/2 connection reuse**

Reuses TCP connections to backend services to reduce latency and overhead from repeated TCP and TLS handshakes.
Configurable idle timeout and max idle connections per host.

Enabled by default with 90s idle timeout and unlimited idle connections per host. Can be disabled globally via
`backend_pool.enabled = false`.

Per-route override available via `force_new_connection = true` to bypass pooling for specific routes (useful for TCP/TLS
fingerprinting scenarios where fresh handshakes are required).

Limitation: Pooling is global or per-route only. No per-backend configuration for pool limits.

## Forwarding Headers

**X-Forwarded-* headers**

Automatically sets X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Port, and X-Forwarded-Proto:

- **X-Forwarded-For** — the TCP peer IP is **appended** to any existing value (preserving the upstream proxy chain, per
  the standard XFF convention). Note: do not trust the leftmost entry as the client IP — use `trusted_proxies` for that.
- **X-Forwarded-Host** — any client-supplied value is **stripped** and replaced with the host the proxy actually routed
  on, so it always agrees with the selected backend.
- **X-Forwarded-Port** / **X-Forwarded-Proto** — set from the connection (peer port, and `https`/`http`), replacing any
  client value.

Limitation: No configurable header names. No support for Forwarded header (RFC 7239).

## Host Header Preservation

**Configurable Host header forwarding**

When `preserve_host` is enabled, the client's original Host header is captured and forwarded to the backend unchanged.
By default (`false`), the request is forwarded with the rewritten upstream target (the backend address) as its
authority, so the backend sees the backend address rather than the client's Host.

This is useful for virtual hosting scenarios where the backend needs to know which domain was originally requested.

Limitation: Global setting only, cannot be configured per-route.

## Granular Timeouts

**Per-direction timeout controls**

Multiple timeout controls to prevent resource exhaustion:

- `upstream_connect_ms` — TCP connect timeout to backend. Optional; if absent, no connect timeout is applied.
- `proxy_idle_ms` (default: 60s) — Inbound idle timeout: HTTP/1.1 `header_read_timeout` + HTTP/2 keep-alive interval.
- `tls_handshake_secs` (default: 15s) — Maximum time for completing TLS handshake.
- `connection_handling_secs` (default: 300s) — Maximum total time for entire connection lifecycle (read + process +
  write).
- `shutdown_secs` (default: 30s) — Graceful shutdown window.
- `keep_alive.upstream_idle_timeout` (default: 60s) — TCP keep-alive interval for proxy → backend connections.

All timeouts are independently configurable.

Metrics track timeout occurrences by type (tls_handshake, connection_handling) for monitoring and alerting.

Limitation: No per-route timeout configuration. The `connection_handling_secs` timeout covers the entire connection
lifecycle.

## Configuration

**TOML-based config files**

Single config file for everything. Dynamic sections (domains, certificates, backends, routes, rate limits, IP
filtering, headers, security headers, connection pool) are hot-reloaded via SIGHUP or file watcher, no connections are
dropped. Static sections (listen addresses, TLS options, fingerprinting flags, logging, telemetry, timeouts) require a
restart.

Config validation available via `--validate` flag (like `nginx -t`) for use in CI/CD pipelines.

Limitation: No API for dynamic config changes.

## Observability

**Prometheus metrics and health checks**

Metrics server runs on a separate port (configurable via `telemetry.metrics_port`). Covers connections, requests, TLS,
fingerprinting, backends, throughput, rate limiting, IP filtering, header manipulation, mTLS, config hot reload, and
TLS certificate hot reload (cert hash + last-reload timestamp + attempt counter).

Request and backend metrics carry a `domain` label so traffic can be broken down per virtual host. The catch-all
(host-less) domain reports as `_default_`, and wildcard domains collapse all their subdomains into the configured
pattern (e.g. `*.example.com`), keeping cardinality bounded by the number of configured domains rather than by request
hosts.

Health endpoints: `/health` (general, alias of liveness), `/ready` (Kubernetes readiness), `/live` (Kubernetes
liveness), `/metrics` (Prometheus). `/live` and `/health` return 200 while the process runs. `/ready` returns 200 once
the proxy's listeners are accepting connections and 503 while starting up or during graceful shutdown.
The eBPF agent's `/ready` returns 200 once its BPF map pins are loaded.

For the full metric list, labels, and example queries, see [TELEMETRY.md](TELEMETRY.md).

Limitation: No distributed tracing. No request logging to files. No custom metrics.

## Hot Reload

**Zero-downtime config updates via SIGHUP or file watcher**

Dynamic config sections are swapped atomically using `ArcSwap`. Each connection takes a config snapshot at accept time
and keeps it for its lifetime, so the new config applies to **new connections**; in-flight connections (including
keep-alive requests) finish on their original snapshot. No connections are dropped (no drain / GOAWAY).

Reload triggers and config:

- **SIGHUP** — always available: `kill -SIGHUP <pid>` or `docker kill --signal=SIGHUP <container>`
- **File watcher** — enabled with `--watch` flag (or `HUGINN_WATCH=true`). Configurable debounce via
  `--watch-delay-secs` / `HUGINN_WATCH_DELAY_SECS` (default: 60s).
- **TOML or YAML** — both formats are supported; the parser is chosen from the file extension (`.yaml`/`.yml` vs `.toml`
  or anything else). Hot reload behaves the same. See [SETTINGS.md](SETTINGS.md).

On reload, if the new config is invalid the proxy keeps the current config and logs the error. If static sections
changed, the proxy logs an error and ignores those changes (restart required).

On load, `--validate`, and every reload the proxy also emits a **non-fatal `WARN`** when a whole-block override (domain
or route) drops a protection the parent had enabled — e.g. a partial `rate_limit`/`ip_filter`/`headers` block that
silently disables a globally-enabled policy. It never aborts, since dropping a policy may be intended.

Limitation: No per-section partial reload. Dynamic config is always swapped as a whole.
