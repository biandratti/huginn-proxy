# Configuration Reference

Configuration is read from a **single file** in **TOML** or **YAML**. The format is chosen from the path’s extension:
`.yaml` / `.yml` → YAML; `.toml` and anything else (including a missing extension) → TOML. Pass the file path as the
positional `CONFIG` argument or via `HUGINN_CONFIG_PATH`:

```bash
huginn-proxy config.toml
huginn-proxy config.yaml
HUGINN_CONFIG_PATH=config.yaml huginn-proxy
```

Validate a config file without starting the proxy (like `nginx -t`):

```bash
huginn-proxy --validate config.toml
huginn-proxy --validate config.yaml
```

**Hot reload:** dynamic sections update on SIGHUP or file-watcher trigger without dropping connections. Static sections
require a process restart — changes are logged as a warning and ignored. See [DEPLOYMENT.md](DEPLOYMENT.md) for the full
static/dynamic split.

---

## Top-level keys

In TOML, these bare keys must appear **before** any `[table]` header. In YAML, use a normal mapping; key order does not
matter.

| Key             | Type | Default | Description                                                                                                                                     |
|-----------------|------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `preserve_host` | bool | `false` | Forward the original `Host` header from the client to the backend. When `false`, the request is forwarded with the backend address as its authority. **Dynamic** (hot-reloadable). |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
preserve_host = false
```

</td>
<td valign="top">

```yaml
preserve_host: false
```

</td>
</tr>
</tbody>
</table>

---

## `[listen]`

Network interfaces and socket options. **Static** — requires restart to change.

| Key           | Type             | Default | Description                                                                            |
|---------------|------------------|---------|----------------------------------------------------------------------------------------|
| `addrs`       | array of strings | —       | One or more `host:port` addresses to bind. IPv6 addresses must be wrapped in brackets. |
| `tcp_backlog` | integer          | `4096`  | Kernel `listen(2)` backlog per socket. Increase under heavy connection bursts.         |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[listen]
addrs = ["0.0.0.0:7000", "[::]:7000"]
# tcp_backlog = 4096
```

</td>
<td valign="top">

```yaml
listen:
  addrs:
    - "0.0.0.0:7000"
    - "[::]:7000"
  # tcp_backlog: 4096
```

</td>
</tr>
</tbody>
</table>

---

## `[[backends]]`

Backend servers for forwarding. Repeat the header for each backend. **Optional** — omitting all backends is valid; requests then return **421** (host matches no domain), **404** (domain matched but no route prefix matches), or **502** (a matching route references a backend with no healthy candidate). **Dynamic** (hot-reloadable).

| Key            | Type   | Default           | Description                                                                                                                        |
|----------------|--------|-------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `address`      | string | —                 | `host:port` of the backend. Used as the pool key — must match exactly what routes reference.                                       |
| `http_version` | string | `null`            | Protocol to use when connecting to this backend. `"http11"`, `"http2"`, or `"preserve"` (negotiate based on what the client used). When unset, the effective default is `preserve` for HTTPS clients and `http11` for plain-HTTP clients. |
| `health_check` | table  | `null` (off)     | Optional active health probe. When set, the proxy tracks per-upstream health and returns **502** to clients when the backend is marked unhealthy. Omit the key entirely to leave the backend unprobed (always treated as healthy). Note: an **empty table** (`health_check = {}`) does *not* mean "off" — it enables a TCP probe with default thresholds. See [`[backends.health_check]`](#backendshealth_check) below. |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[[backends]]
address = "backend-a:9000"
http_version = "preserve"

[[backends]]
address = "backend-b:9000"
http_version = "http11"
```

</td>
<td valign="top">

```yaml
backends:
  - address: "backend-a:9000"
    http_version: preserve
  - address: "backend-b:9000"
    http_version: http11
```

</td>
</tr>
</tbody>
</table>

### `[backends.health_check]`

Optional. **Dynamic** (hot-reloadable). If absent, the backend is always treated as healthy for the gate (no background task).

| Key                    | Type   | Default  | Description |
|------------------------|--------|----------|-------------|
| `type`                 | string | `tcp`    | `tcp` (TCP 3-way handshake to `address`) or `http` (HTTP/1.1 `GET` to `http://{address}{path}`; plain HTTP only, no TLS to upstream). |
| `path`                 | string | —        | Required when `type = "http"`: must start with `/` (e.g. `/` or `/ready`). Ignored for `tcp`. |
| `expected_status`      | int    | `200`    | For `http` only: response status must match (e.g. `200`, `204`). |
| `interval_secs`        | int    | `10`     | Time between probes. |
| `timeout_secs`         | int    | `5`      | Per-probe budget (must be ≤ `interval_secs`). Encompasses connect, request, and body drain for `http`. |
| `unhealthy_threshold`  | int    | `3`      | Consecutive failed probes before marking upstream unhealthy. |
| `healthy_threshold`    | int    | `2`      | Consecutive successful probes before marking upstream healthy again. |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[[backends]]
address = "app:8080"
http_version = "http11"
# HTTP GET http://app:8080/ready must return 200
health_check = { type = "http", path = "/ready", expected_status = 200 }
```

</td>
<td valign="top">

```yaml
backends:
  - address: "app:8080"
    http_version: http11
    health_check:
      type: http
      path: /ready
      expected_status: 200
```

</td>
</tr>
</tbody>
</table>

---

## `[[domains]]`

Domain entries group a TLS certificate with its path-based routes. Each entry handles one
hostname (or wildcard), or acts as a catch-all. **Dynamic** (hot-reloadable). **Optional** —
omitting all domains is valid; the proxy binds but returns **421 (Misdirected Request)** for all
requests, since no host can match.

The request host is resolved from the HTTP-layer authority for **all** protocol versions —
`:authority` (HTTP/2) or absolute-form target → `Host` header (RFC 7230 §5.4) — exactly like
nginx/Traefik. TLS SNI is **not** used for routing; it only selects the certificate at the TLS
layer (and drives `sni_strict`). This keeps routing correct for coalesced HTTP/2 connections,
where one TLS session is reused across origins under the same certificate and each request
carries its own `:authority`.

Host matching order, against that resolved host:
1. Exact match — `"api.example.com"`
2. Wildcard match — `"*.example.com"` (one level only; does not match `a.b.example.com`)
3. **Catch-all** — the entry with no `host` key, if present. Matches any host, including IP
   literals (`127.0.0.1`, `::1`) and `localhost`. Mirrors a Traefik router with no `Host()`
   rule.
4. No match → HTTP 421 (Misdirected Request).

Host matching is **case-insensitive**: `host` values are lowercased at load and compared
against the lowercased request host. The config is rejected at load if two domains share the
same `host` (after lowercasing) or if more than one catch-all (host-less) domain is defined.

`X-Forwarded-Host` sent to the backend mirrors this resolved routing host (never a
client-supplied `X-Forwarded-Host`), so it always agrees with the backend the request reaches.

Because routing follows the request authority rather than SNI, a reused (coalesced) HTTP/2
connection can in principle carry a request for a host served by a *different* certificate.
Huginn rejects that with **`421 Misdirected Request`**, always — the same default protection
nginx and Apache `mod_http2` apply (RFC 9110 §15.5.20 / RFC 7540 §9.1.2). The check is on a
TLS connection that presented an SNI: if the request's resolved host is not covered by the
**same certificate** the SNI selected, it gets 421. It compares certificate coverage, **not**
literal `authority == SNI`, so legitimate coalescing keeps working — a shared wildcard entry
(`api`/`docs.example.com` under `*.example.com`) or distinct `[[domains]]` pointing at the same
SAN cert file both resolve to the same certificate and are allowed. It is not configurable: it
only fires on genuinely cross-certificate requests, so there is no legitimate traffic to exempt.
Plain HTTP and TLS connections without SNI are unaffected (there is no certificate scope to
enforce).

**TLS certificate selection** is independent of routing and driven by SNI:
- SNI matches an exact/wildcard domain → that domain's cert.
- No SNI (IP clients, RFC 6066) or SNI matches nothing → the **default certificate**, i.e. the
  cert on the catch-all (`host`-less) entry. Equivalent to Traefik's `defaultCertificate`.
- Unknown/absent SNI with no default cert → rejected with TLS `unrecognized_name` (nothing to
  serve).

  This default-cert fallback applies only to **unmatched/absent SNI at runtime**. It is **not** a
  fallback for a *declared* domain that omits `cert`: under `[tls]` every domain must declare its
  own `cert` (config validation rejects a TLS domain without one), so the default cert lives on
  the catch-all (`host`-less) entry and that entry, under `[tls]`, must declare a `cert` too.
- For strict hostname enforcement, set `[tls.options].sni_strict = true` (see below). This is
  full parity with Traefik's `sniStrict: true`: the default-cert fallback is disabled for
  **both** unmatched-hostname SNI **and** no-SNI connections, so IP-literal HTTPS clients (and
  any client that omits SNI) are rejected with `unrecognized_name`. Leave it `false` (default)
  if you need IP-literal access or no-SNI clients to keep working via the default cert.

| Key         | Type   | Default | Description                                                                                      |
|-------------|--------|---------|--------------------------------------------------------------------------------------------------|
| `host`      | string | `null`  | Domain pattern for host matching: exact (`api.example.com`) or single-level wildcard (`*.example.com`). **Omit for a catch-all** that matches any host; under `[tls]` its cert is the TLS default certificate. |
| `cert`      | table  | `null`  | Certificate source for this domain. `{ type = "file", cert_path = "…", key_path = "…" }` for a static PEM cert, or `{ type = "acme" }` for an ACME-managed cert (requires the global `[acme]` block — TLS-ALPN-01, exact hosts only). **Under `[tls]`, every domain must declare `cert`** (or resolve to ACME-by-default when `[acme]` is configured) — there is **no implicit default-cert fallback** for a declared domain; a TLS domain without `cert` is a configuration error. **Omit only** for plain-HTTP-only domains (no `[tls]`). |
| `headers`   | table  | —       | Domain-level header manipulation. Merged between global and route-level headers.                 |
| `security`  | table  | —       | Per-domain security overrides (`ip_filter`, `rate_limit`, `headers`). See [`[domains.security]`](#domainssecurity) below. |
| `fingerprinting` | bool | `null` (inherit) | Domain-level fingerprint-header **injection** gate. Resolved per route as `route.or(domain).unwrap_or(true)`. Controls header injection only; capture is the static global `[fingerprint]`. |
| `routes`    | array  | `[]`    | Path-based routing rules scoped to this domain. Same fields as the former `[[routes]]` entries.  |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[[domains]]
host = "api.example.com"
cert = { type = "file", cert_path = "/config/certs/api.crt", key_path = "/config/certs/api.key" }

  [[domains.routes]]
  prefix = "/v2"
  backend = "api-backend:9000"
  fingerprinting = true

  [[domains.routes]]
  prefix = "/"
  backend = "web-backend:8080"

[[domains]]
host = "*.example.com"
cert = { type = "file", cert_path = "/config/certs/wildcard.crt", key_path = "/config/certs/wildcard.key" }

  [[domains.routes]]
  prefix = "/"
  backend = "web-backend:8080"
```

</td>
<td valign="top">

```yaml
domains:
  - host: "api.example.com"
    cert:
      type: file
      cert_path: "/config/certs/api.crt"
      key_path:  "/config/certs/api.key"
    routes:
      - prefix: "/v2"
        backend: "api-backend:9000"
        fingerprinting: true
      - prefix: "/"
        backend: "web-backend:8080"

  - host: "*.example.com"
    cert:
      type: file
      cert_path: "/config/certs/wildcard.crt"
      key_path:  "/config/certs/wildcard.key"
    routes:
      - prefix: "/"
        backend: "web-backend:8080"
```

</td>
</tr>
</tbody>
</table>

**Catch-all example** — one host-less entry serves any host (handy for local/IP access or a
default site). Its cert becomes the TLS default certificate:

```yaml
domains:
  # No `host:` → matches localhost, 127.0.0.1, ::1, or any other host.
  - cert:
      type: file
      cert_path: "/config/certs/server.crt"
      key_path:  "/config/certs/server.key"
    routes:
      - prefix: "/"
        backend: "web-backend:8080"
```

### Scope & override summary

Where each policy can be set (**global** `[security]`/`[headers]` → **domain** `[domains.*]` →
**route** `[domains.routes.*]`) and how a more specific scope combines with the parent:

| Policy | Global | Domain | Route | How it overrides |
|---|:---:|:---:|:---:|---|
| `ip_filter` (ACL) | ✅ | ✅ | ✅ | **Whole-block replace** — most specific scope wins entirely. Route filter checked after route match. |
| `rate_limit` (incl. `limit_by`) | ✅ | ✅ | ✅ | **Whole-block replace** — most specific scope wins entirely. |
| `security.headers` (HSTS/CSP/custom) | ✅ | ✅ | ✅ | **Whole-block replace** — most specific scope wins entirely. |
| `[headers]` (add/remove request/response) | ✅ | ✅ | ✅ | **Additive cascade** — all scopes accumulate; per header name the most specific wins. |
| `fingerprinting` (header injection) | — | ✅ | ✅ | `route.or(domain).unwrap_or(true)`. Capture itself is the static global `[fingerprint]`. |
| `trusted_proxies` (client-IP from XFF) | ✅ | ❌ | ❌ | Global only — network-topology property, not overridable per scope. |
| `max_connections` | ✅ | ❌ | ❌ | Process-level (static); global only. |

**Whole-block replace** means the block is taken as a unit: a partial override drops the parent's
other keys (e.g. a route `rate_limit` without `enabled = true` disables the limit for that route).
Re-state every key you want to keep. The proxy logs a non-fatal `WARN` (boot, `--validate`, and
every hot reload) when an override drops a parent-enabled protection. See
[`[domains.security]`](#domainssecurity), [`[domains.routes.security]`](#domainsroutessecurity),
and [Header manipulation vs. security headers](#header-manipulation-vs-security-headers).

### `[domains.routes]`

Path-prefix routing rules scoped to the parent domain. Longest prefix wins; declaration
order does not matter within a domain.

| Key                    | Type   | Default | Description                                                                                                                                                                                    |
|------------------------|--------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `prefix`               | string | —       | URL path prefix to match. Use `"/"` as a catch-all.                                                                                                                                            |
| `backend`              | string | —       | Backend address to forward to. Must match a `[[backends]].address` exactly.                                                                                                                    |
| `fingerprinting`       | bool   | inherit | Inject TLS/HTTP fingerprint headers (`x-tls-ja4*`, `x-http2-akamai`, `x-tcp-p0f`) for this route. Unset inherits the domain's `fingerprinting`, then the built-in default `true`.            |
| `force_new_connection` | bool   | `false` | Bypass the connection pool — opens a fresh TCP+TLS connection per request.                                                                                                                     |
| `replace_path`         | string | `null`  | Path prefix replacement. Empty string (`""`) strips the prefix. Absent = forward as-is.                                                                                                       |
| `security`             | table  | —       | Per-route security overrides (`ip_filter`, `rate_limit`, `headers`). Each present sub-block **fully replaces** the domain-effective policy for this route. See [`[domains.routes.security]`](#domainsroutessecurity) below. |
| `headers`              | table  | —       | Per-route header manipulation (add/remove). Applied after global and domain-level headers (additive cascade — see [Header manipulation vs. security headers](#header-manipulation-vs-security-headers)). |

### `[domains.routes.security]`

Per-route security policy. Mirrors [`[domains.security]`](#domainssecurity) one level deeper:
each sub-block (`ip_filter`, `rate_limit`, `headers`), **when present, fully replaces** the
domain-effective policy for this route (whole-block replace — **not** a field-level merge). A
sub-block you omit inherits the domain-effective (or global) policy. Security policy lives under
`security` at every scope — global (`[security]`), domain (`[domains.security]`), and route — so
the path is consistent.

> **Footgun:** because the block is replaced wholesale, a *partial* override silently drops the
> sibling keys of the policy it replaces. For example, a route `rate_limit` that sets only
> `requests_per_second` (without `enabled = true`) **disables** the limit for that route, because
> the unset `enabled` defaults to `false`. The proxy emits a non-fatal `warn!` at load and on every
> hot reload when an override drops a protection the parent had enabled (e.g. `WARN ... headers
> override drops parent-enabled protections [CSP]`). Re-state every key you want to keep.

| Key          | Type  | Default | Description                                                                                                      |
|--------------|-------|---------|------------------------------------------------------------------------------------------------------------------|
| `ip_filter`  | table | —       | IP ACL for this route. Replaces the domain/global `ip_filter`. Same fields as [`[security.ip_filter]`](#securityip_filter). Checked after route match (router-level ACL). |
| `rate_limit` | table | —       | Rate limit policy for this route. Replaces the domain/global `rate_limit`. Same fields as [`[security.rate_limit]`](#securityrate_limit). |
| `headers`    | table | —       | Security headers for this route. Replaces the domain/global `security.headers`. Same fields as [`[security.headers]`](#securityheaders). |

### `[domains.security]`

Per-domain security policy. Each sub-block, **when present, fully replaces** the matching
global `[security]` policy for this domain (whole-block replace — not a field-level merge), and
can also *disable* a globally-enabled policy (e.g. `ip_filter.mode = "disabled"` or
`rate_limit.enabled = false`). A sub-block you omit inherits the global policy. `max_connections`
is global only (process-level) and is not part of this block.

| Key          | Type  | Default | Description                                                                                                   |
|--------------|-------|---------|---------------------------------------------------------------------------------------------------------------|
| `ip_filter`  | table | —       | IP ACL for this domain. Replaces global [`[security.ip_filter]`](#securityip_filter) when present.            |
| `rate_limit` | table | —       | Rate limit policy for this domain. Replaces global [`[security.rate_limit]`](#securityrate_limit) when present. A per-route `[domains.routes.security.rate_limit]` then replaces this domain-effective policy for that route (whole-block, not a merge). |
| `headers`    | table | —       | Security headers for this domain. Replaces global [`[security.headers]`](#securityheaders) when present.      |

Precedence is **global → domain → route** for all three policies (`ip_filter`, `rate_limit`,
`headers`): the most specific scope that sets a block wins **entirely** (whole-block replace, no
field merge). Rate limiters are keyed per domain, so the same route prefix under two domains is
tracked independently. `fingerprinting` (header injection) follows the same precedence:
`route.or(domain).unwrap_or(true)`.

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[[domains]]
host = "api.example.com"
cert = { type = "file", cert_path = "/config/certs/api.crt", key_path = "/config/certs/api.key" }

  [[domains.routes]]
  prefix = "/"
  backend = "api-backend:9000"

  # Only this domain: allowlist + tighter rate limit + its own HSTS.
  [domains.security.ip_filter]
  mode = "allowlist"
  allowlist = ["10.0.0.0/8"]

  [domains.security.rate_limit]
  enabled = true
  requests_per_second = 50
  burst = 100

  [domains.security.headers.hsts]
  enabled = true
  max_age = 63072000
```

</td>
<td valign="top">

```yaml
domains:
  - host: "api.example.com"
    cert:
      type: file
      cert_path: "/config/certs/api.crt"
      key_path:  "/config/certs/api.key"
    routes:
      - prefix: "/"
        backend: "api-backend:9000"
    security:
      ip_filter:
        mode: "allowlist"
        allowlist: ["10.0.0.0/8"]
      rate_limit:
        enabled: true
        requests_per_second: 50
        burst: 100
      headers:
        hsts:
          enabled: true
          max_age: 63072000
```

</td>
</tr>
</tbody>
</table>

### `[domains.headers]`

Domain-level header manipulation. Applied after global `[headers]` and before
route-level `[domains.routes.headers]`. Same shape as [`[headers]`](#headers).

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[[domains]]
host = "api.example.com"
cert = { type = "file", cert_path = "/config/certs/api.crt", key_path = "/config/certs/api.key" }

[domains.headers.response]
add = [
  { name = "Strict-Transport-Security", value = "max-age=31536000" },
  { name = "Content-Security-Policy",   value = "default-src 'self'" },
]

  [[domains.routes]]
  prefix = "/v2"
  backend = "api-backend:9000"

  [domains.routes.headers.request]
  add = [{ name = "X-API-Version", value = "2" }]
```

</td>
<td valign="top">

```yaml
domains:
  - host: "api.example.com"
    cert:
      type: file
      cert_path: "/config/certs/api.crt"
      key_path:  "/config/certs/api.key"
    headers:
      response:
        add:
          - name: "Strict-Transport-Security"
            value: "max-age=31536000"
          - name: "Content-Security-Policy"
            value: "default-src 'self'"
    routes:
      - prefix: "/v2"
        backend: "api-backend:9000"
        headers:
          request:
            add:
              - name: "X-API-Version"
                value: "2"
```

</td>
</tr>
</tbody>
</table>

---

## `[headers]`

Global header manipulation applied to every request/response. **Dynamic** (hot-reloadable).

### `[headers.request]`

| Key      | Type                     | Default | Description                                                            |
|----------|--------------------------|---------|------------------------------------------------------------------------|
| `add`    | array of `{name, value}` | `[]`    | Headers to add to the upstream request. Overwrites if already present. |
| `remove` | array of strings         | `[]`    | Header names to remove from the upstream request.                      |

### `[headers.response]`

| Key      | Type                     | Default | Description                                      |
|----------|--------------------------|---------|--------------------------------------------------|
| `add`    | array of `{name, value}` | `[]`    | Headers to add to the client response.           |
| `remove` | array of strings         | `[]`    | Header names to remove from the client response. |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

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

</td>
<td valign="top">

```yaml
headers:
  request:
    remove:
      - "X-Forwarded-Server"
    add:
      - name: "X-Proxy-Name"
        value: "huginn-proxy"
  response:
    remove:
      - "Server"
      - "X-Powered-By"
    add:
      - name: "X-Proxy"
        value: "huginn-proxy"
```

</td>
</tr>
</tbody>
</table>

### Header manipulation vs. security headers

There are two header mechanisms with **different override semantics** — this is intentional:

- **`[headers]` (add/remove), the additive cascade.** Global → domain → route are applied in
  order and **accumulate**; for a given header name the most specific scope wins (last-writer).
  Nothing is "replaced wholesale" — a route adding `X-API-Version` does not wipe a global
  `X-Proxy` header. This mirrors **chaining `headers` middlewares in Traefik**, where each
  middleware in the chain runs in turn.
- **`security.headers` (HSTS/CSP/custom), whole-block replace.** Like the other security policies
  (`ip_filter`, `rate_limit`), the most specific scope that sets a `security.headers` block
  replaces the parent's block **entirely** (see [`[domains.routes.security]`](#domainsroutessecurity)).

Rule of thumb: `[headers]` is for free-form request/response header plumbing (cascades);
`security.headers` is a security *policy* (replaced as a unit, audited for partial-override drops).

---

## `[tls]`

TLS termination options. Omit the entire section to run as plain HTTP. **Static** — requires
restart to change. Certificates are configured per domain under `[[domains]]` (see below).

| Key    | Type             | Default | Description                                                                                                 |
|--------|------------------|---------|-------------------------------------------------------------------------------------------------------------|
| `alpn` | array of strings | `[]`    | ALPN protocols to advertise. Use `["h2", "http/1.1"]` to support both HTTP/2 and HTTP/1.1 with negotiation. |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[tls]
alpn = ["h2", "http/1.1"]
```

</td>
<td valign="top">

```yaml
tls:
  alpn:
    - "h2"
    - "http/1.1"
```

</td>
</tr>
</tbody>
</table>

### `[tls.options]`

| Key                 | Type             | Default          | Description                                                |
|---------------------|------------------|------------------|------------------------------------------------------------|
| `versions`          | array of strings | `["1.2", "1.3"]` | Allowed TLS versions. Values: `"1.2"`, `"1.3"`. **Currently parsed and validated but not enforced** — see note below. |
| `min_version`       | string           | `null`           | Minimum TLS version (`"1.2"` or `"1.3"`). Mutually exclusive with an explicit `versions` list. **Currently parsed and validated but not enforced** — see note below. |
| `max_version`       | string           | `null`           | Maximum TLS version (`"1.2"` or `"1.3"`). Mutually exclusive with an explicit `versions` list. **Currently parsed and validated but not enforced** — see note below. |
| `cipher_suites`     | array of strings | all supported    | Named cipher suites. Restrict to tighten security posture. Applied to the TLS stack. |
| `curve_preferences` | array of strings | all supported    | Named elliptic curves for key exchange. **Currently parsed and validated but not enforced** — see note below. |
| `sni_strict`        | bool             | `false`          | When `true`, disable the default-cert fallback entirely (full parity with Traefik's `sniStrict`): reject (`unrecognized_name`) both a TLS connection whose SNI matches no domain cert **and** a connection that sends no SNI (IP-literal clients). When `false`, both fall back to the default cert. Production hardening against unknown-hostname / no-SNI access. |

> **Note:** `cipher_suites` and `sni_strict` are applied to the TLS stack. `versions`, `min_version`,
> `max_version`, and `curve_preferences` are currently validated at load but **not** applied — the
> acceptor is built with rustls' safe defaults (TLS 1.2 **and** 1.3, default curve preferences). Do
> not rely on these four keys to restrict the negotiated TLS version or curves yet.

> **Misdirected requests (HTTP 421)** are handled automatically and are not configurable. On a
> coalesced HTTP/2 connection, any request whose host is served by a different certificate than
> the connection's SNI selected is rejected with `421 Misdirected Request` — the same default
> behaviour as nginx and Apache `mod_http2`. Hosts sharing one certificate (wildcard or SAN)
> still coalesce. See the `[[domains]]` section above.

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[tls.options]
versions = ["1.2", "1.3"]
cipher_suites = [
    "TLS13_AES_128_GCM_SHA256",
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
]
curve_preferences = ["X25519", "secp256r1", "secp384r1"]
sni_strict = false   # set true in production to reject unknown-hostname SNI
```

</td>
<td valign="top">

```yaml
tls:
  options:
    versions:
      - "1.2"
      - "1.3"
    cipher_suites:
      - "TLS13_AES_128_GCM_SHA256"
      - "TLS13_AES_256_GCM_SHA384"
      - "TLS13_CHACHA20_POLY1305_SHA256"
      - "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
      - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    curve_preferences:
      - "X25519"
      - "secp256r1"
      - "secp384r1"
    sni_strict: false   # set true in production to reject unknown-hostname SNI
```

</td>
</tr>
</tbody>
</table>

### `[tls.client_auth]`

Mutual TLS (mTLS). **Present** ⇒ clients must present a certificate signed by `ca_cert_path`'s
CA; **omit the block** to disable mTLS. **Static**.

> Note: mTLS is incompatible with ACME. A domain that resolves to `cert = { type = "acme" }`
> together with a global `client_auth` is rejected at load (the TLS-ALPN-01 challenge presents no
> client certificate). Use a static `cert = { type = "file" }` if you need mTLS.

| Key            | Type   | Default | Description                                                              |
|----------------|--------|---------|--------------------------------------------------------------------------|
| `ca_cert_path` | string | —       | Path to the client CA certificate PEM file (one or more CA certs). Required when the block is present. |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
# Require client certificates signed by this CA
[tls.client_auth]
ca_cert_path = "/config/certs/ca.crt"
```

</td>
<td valign="top">

```yaml
# Require client certificates signed by this CA
tls:
  client_auth:
    ca_cert_path: "/config/certs/ca.crt"
```

</td>
</tr>
</tbody>
</table>

### `[tls.session_resumption]`

| Key            | Type    | Default | Description                                                                    |
|----------------|---------|---------|--------------------------------------------------------------------------------|
| `enabled`      | bool    | `true`  | Enable TLS session resumption (TLS 1.2 session IDs + TLS 1.3 session tickets). |
| `max_sessions` | integer | `256`   | TLS 1.2 server-side session cache size.                                        |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[tls.session_resumption]
enabled = true
max_sessions = 256
```

</td>
<td valign="top">

```yaml
tls:
  session_resumption:
    enabled: true
    max_sessions: 256
```

</td>
</tr>
</tbody>
</table>

---

## `[fingerprint]`

Feature flags for passive fingerprinting. **Static** — eBPF programs are loaded at startup.

| Key            | Type    | Default | Description                                                                                                                                                |
|----------------|---------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `tls_enabled`  | bool    | `true`  | Extract TLS (JA4) fingerprints and inject `x-tls-ja4*` headers.                                                                                     |
| `http_enabled` | bool    | `true`  | Extract HTTP/2 (Akamai) fingerprints and inject `x-http2-akamai` header.                                                                              |
| `tcp_enabled`  | bool    | `false` | Extract TCP SYN (p0f-style) fingerprints via eBPF/XDP and inject `x-tcp-p0f` header. Requires the `ebpf-tcp` build feature and Linux kernel ≥ 5.11. |
| `max_capture`  | integer | `65536` | Maximum bytes captured per HTTP/2 connection for fingerprinting.                                                                                           |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[fingerprint]
tls_enabled = true
http_enabled = true
tcp_enabled = false
max_capture = 65536
```

</td>
<td valign="top">

```yaml
fingerprint:
  tls_enabled: true
  http_enabled: true
  tcp_enabled: false
  max_capture: 65536
```

</td>
</tr>
</tbody>
</table>

---

## `[logging]`

**Static** — logger is initialized once at startup.

| Key           | Type   | Default  | Description                                                                                                           |
|---------------|--------|----------|-----------------------------------------------------------------------------------------------------------------------|
| `level`       | string | `"info"` | Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`. Overridable with the `RUST_LOG` environment variable. |
| `show_target` | bool   | `false`  | Include the Rust module path in log lines (useful for debugging).                                                     |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[logging]
level = "info"
show_target = false
```

</td>
<td valign="top">

```yaml
logging:
  level: "info"
  show_target: false
```

</td>
</tr>
</tbody>
</table>

---

## `[telemetry]`

Metrics server and OpenTelemetry settings. **Static** — the metrics listener binds at startup.

| Key              | Type    | Default  | Description                                                                                                                       |
|------------------|---------|----------|-----------------------------------------------------------------------------------------------------------------------------------|
| `metrics_port`   | integer | `null`   | Port for the Prometheus metrics + health-check HTTP server. Omit to disable. Endpoints: `/metrics`, `/health`, `/ready`, `/live`. |
| `otel_log_level` | string  | `"warn"` | OpenTelemetry SDK internal log level. Does not affect application logs.                                                           |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[telemetry]
metrics_port = 9090
otel_log_level = "warn"
```

</td>
<td valign="top">

```yaml
telemetry:
  metrics_port: 9090
  otel_log_level: "warn"
```

</td>
</tr>
</tbody>
</table>

---

## `[timeout]`

Connection timeout controls. **Static** — applied once at startup; the connection pool and acceptor are built with these
values.

| Key                        | Type    | Default             | Description                                                                                                                           |
|----------------------------|---------|---------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| `upstream_connect_ms`      | integer | absent (no timeout) | TCP connect timeout to backend in milliseconds. Absent or omitted = no timeout.                                                       |
| `proxy_idle_ms`            | integer | `60000`             | Inbound idle timeout in milliseconds. Applied as HTTP/1.1 `header_read_timeout` and HTTP/2 keep-alive interval.                       |
| `tls_handshake_secs`       | integer | `15`                | Maximum seconds to complete the client TLS handshake. Slow/malicious clients that stall the handshake are disconnected.               |
| `connection_handling_secs` | integer | `300`               | Maximum total seconds for a full connection lifecycle (read request + proxy + write response). Guards against extremely slow clients. |
| `shutdown_secs`            | integer | `30`                | Graceful shutdown window. In-flight requests have this many seconds to complete before the process exits.                             |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[timeout]
upstream_connect_ms = 5000
proxy_idle_ms = 60000
tls_handshake_secs = 15
connection_handling_secs = 300
shutdown_secs = 30
```

</td>
<td valign="top">

```yaml
timeout:
  upstream_connect_ms: 5000
  proxy_idle_ms: 60000
  tls_handshake_secs: 15
  connection_handling_secs: 300
  shutdown_secs: 30
```

</td>
</tr>
</tbody>
</table>

### `[timeout.keep_alive]`

HTTP/1.1 keep-alive and upstream TCP keepalive. Applies only to HTTP/1.1; HTTP/2 connections are always persistent.

| Key                     | Type    | Default | Description                                                                                                                                                                                   |
|-------------------------|---------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `enabled`               | bool    | `true`  | Enable HTTP/1.1 persistent connections (`Connection: keep-alive`).                                                                                                                            |
| `upstream_idle_timeout` | integer | `60`    | TCP keepalive interval in seconds for proxy → backend connections. Sets how often keepalive packets are sent to detect dead backend connections. Aligned with rpxy's `upstream_idle_timeout`. |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[timeout.keep_alive]
enabled = true
upstream_idle_timeout = 60
```

</td>
<td valign="top">

```yaml
timeout:
  keep_alive:
    enabled: true
    upstream_idle_timeout: 60
```

</td>
</tr>
</tbody>
</table>

---

## `[backend_pool]`

HTTP connection pool for proxy → backend connections. **Dynamic** (hot-reloadable). Changing this triggers pool
recreation and draining of old connections.

| Key                      | Type    | Default | Description                                                                                                            |
|--------------------------|---------|---------|------------------------------------------------------------------------------------------------------------------------|
| `enabled`                | bool    | `true`  | Enable connection pooling. Set to `false` to open a new connection for every request (not recommended for production). |
| `idle_timeout`           | integer | `90`    | Seconds before an idle pooled connection is closed and removed.                                                        |
| `pool_max_idle_per_host` | integer | `0`     | Maximum idle connections kept per backend host. `0` = unlimited.                                                       |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[backend_pool]
enabled = true
idle_timeout = 90
pool_max_idle_per_host = 0
```

</td>
<td valign="top">

```yaml
backend_pool:
  enabled: true
  idle_timeout: 90
  pool_max_idle_per_host: 0
```

</td>
</tr>
</tbody>
</table>

---

## `[security]`

### Top-level security keys

| Key               | Type         | Default | Description                                                                         |
|-------------------|--------------|---------|-------------------------------------------------------------------------------------|
| `max_connections` | integer      | `512`   | Maximum concurrent client connections. **Static** — enforced at the acceptor level. |
| `trusted_proxies` | string array | `[]`    | Trusted reverse-proxy CIDRs used to resolve the real client IP from `X-Forwarded-For`. **Global only** — a property of the network topology, *not* overridable per domain/route. When empty (default), the non-forgeable TCP peer IP is used. When set and the peer is a trusted proxy, XFF is walked right-to-left and the first IP **not** in this list is used. Consumed by rate limiting (`limit_by = "ip" \| "combined"`). **Dynamic** (hot-reloadable). Accepts CIDR notation. |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[security]
max_connections = 512
# Trusted load balancers in front of the proxy; recover the real client IP from XFF.
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
```

</td>
<td valign="top">

```yaml
security:
  max_connections: 512
  # Trusted load balancers in front of the proxy; recover the real client IP from XFF.
  trusted_proxies:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
```

</td>
</tr>
</tbody>
</table>

### `[security.ip_filter]`

IP-based access control. **Dynamic** (hot-reloadable).

| Key         | Type             | Default      | Description                                                                                                |
|-------------|------------------|--------------|------------------------------------------------------------------------------------------------------------|
| `mode`      | string           | `"disabled"` | Filter mode: `"disabled"`, `"allowlist"` (only listed IPs pass), or `"denylist"` (listed IPs are blocked). |
| `allowlist` | array of strings | `[]`         | CIDR ranges allowed when `mode = "allowlist"`. Supports IPv4 and IPv6. Empty allowlist blocks all traffic. |
| `denylist`  | array of strings | `[]`         | CIDR ranges blocked when `mode = "denylist"`. Supports IPv4 and IPv6. Empty denylist allows all traffic.   |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
# Disabled (default)
[security.ip_filter]
mode = "disabled"

# Allowlist: only these IPs can connect
[security.ip_filter]
mode = "allowlist"
allowlist = ["10.0.0.0/8", "192.168.1.0/24", "::1/128"]

# Denylist: block these IPs
[security.ip_filter]
mode = "denylist"
denylist = ["192.168.1.100/32", "10.99.0.0/16"]
```

</td>
<td valign="top">

```yaml
# Disabled (default)
security:
  ip_filter:
    mode: "disabled"

# Allowlist: only these IPs can connect
security:
  ip_filter:
    mode: "allowlist"
    allowlist:
      - "10.0.0.0/8"
      - "192.168.1.0/24"
      - "::1/128"

# Denylist: block these IPs
security:
  ip_filter:
    mode: "denylist"
    denylist:
      - "192.168.1.100/32"
      - "10.99.0.0/16"
```

</td>
</tr>
</tbody>
</table>

### `[security.rate_limit]`

Global rate limiting. **Dynamic** (hot-reloadable). Per-domain override via
`[domains.security.rate_limit]` and per-route override via `[domains.routes.security.rate_limit]`,
each a **whole-block replace** (not a field-level merge).

The real client IP used for `limit_by = "ip" | "combined"` is resolved from the global
[`[security].trusted_proxies`](#top-level-security-keys).

| Key                   | Type    | Default | Description                                                                         |
|-----------------------|---------|---------|-------------------------------------------------------------------------------------|
| `enabled`             | bool    | `false` | Enable global rate limiting.                                                        |
| `requests_per_second` | integer | `1000`  | Sustained request rate allowed.                                                     |
| `burst`               | integer | `2000`  | Maximum burst size above the sustained rate.                                        |
| `window_seconds`      | integer | `1`     | Sliding window in seconds for the token bucket refill.                              |
| `limit_by`            | string       | `"ip"`  | Key used to track limits: `"ip"`, `"header"`, `"route"`, `"combined"` (IP + route). |
| `limit_by_header`     | string       | `null`  | Header name to use as the rate limit key when `limit_by = "header"`.                |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[security.rate_limit]
enabled = true
requests_per_second = 1000
burst = 2000
window_seconds = 1
limit_by = "ip"
```

</td>
<td valign="top">

```yaml
security:
  rate_limit:
    enabled: true
    requests_per_second: 1000
    burst: 2000
    window_seconds: 1
    limit_by: "ip"
```

</td>
</tr>
</tbody>
</table>

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
# Rate limit by API key header
[security.rate_limit]
enabled = true
requests_per_second = 200
burst = 400
limit_by = "header"
limit_by_header = "X-API-Key"
```

</td>
<td valign="top">

```yaml
# Rate limit by API key header
security:
  rate_limit:
    enabled: true
    requests_per_second: 200
    burst: 400
    limit_by: "header"
    limit_by_header: "X-API-Key"
```

</td>
</tr>
</tbody>
</table>

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
# Rate limit by real client IP behind a trusted load balancer.
# The client IP is resolved from the GLOBAL `[security].trusted_proxies`
# (walking XFF right-to-left); without it the TCP peer IP is used.
[security]
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]

[security.rate_limit]
enabled = true
requests_per_second = 500
burst = 1000
limit_by = "ip"
```

</td>
<td valign="top">

```yaml
# Rate limit by real client IP behind a trusted load balancer.
# The client IP is resolved from the GLOBAL security.trusted_proxies
# (walking XFF right-to-left); without it the TCP peer IP is used.
security:
  trusted_proxies:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
  rate_limit:
    enabled: true
    requests_per_second: 500
    burst: 1000
    limit_by: "ip"
```

</td>
</tr>
</tbody>
</table>

### `[security.headers]`

Security headers added to every response. **Dynamic** (hot-reloadable).

| Key      | Type                     | Default | Description                               |
|----------|--------------------------|---------|-------------------------------------------|
| `custom` | array of `{name, value}` | `[]`    | Arbitrary headers added to all responses. |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[security.headers]
custom = [
    { name = "X-Frame-Options", value = "DENY" },
    { name = "X-Content-Type-Options", value = "nosniff" },
    { name = "Referrer-Policy", value = "strict-origin-when-cross-origin" },
]
```

</td>
<td valign="top">

```yaml
security:
  headers:
    custom:
      - name: "X-Frame-Options"
        value: "DENY"
      - name: "X-Content-Type-Options"
        value: "nosniff"
      - name: "Referrer-Policy"
        value: "strict-origin-when-cross-origin"
```

</td>
</tr>
</tbody>
</table>

#### `[security.headers.hsts]`

HTTP Strict Transport Security. Only meaningful when TLS is enabled.

| Key                  | Type    | Default    | Description                                                 |
|----------------------|---------|------------|-------------------------------------------------------------|
| `enabled`            | bool    | `false`    | Add `Strict-Transport-Security` header to responses.        |
| `max_age`            | integer | `31536000` | `max-age` in seconds (default = 1 year).                    |
| `include_subdomains` | bool    | `false`    | Add `includeSubDomains` directive.                          |
| `preload`            | bool    | `false`    | Add `preload` directive (for HSTS preload list submission). |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[security.headers.hsts]
enabled = true
max_age = 31536000
include_subdomains = true
preload = false
```

</td>
<td valign="top">

```yaml
security:
  headers:
    hsts:
      enabled: true
      max_age: 31536000
      include_subdomains: true
      preload: false
```

</td>
</tr>
</tbody>
</table>

#### `[security.headers.csp]`

Content Security Policy.

| Key       | Type   | Default                | Description                                        |
|-----------|--------|------------------------|----------------------------------------------------|
| `enabled` | bool   | `false`                | Add `Content-Security-Policy` header to responses. |
| `policy`  | string | `"default-src 'self'"` | Full CSP policy string.                            |

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
[security.headers.csp]
enabled = true
policy = "default-src 'self'; script-src 'self' 'unsafe-inline'"
```

</td>
<td valign="top">

```yaml
security:
  headers:
    csp:
      enabled: true
      policy: "default-src 'self'; script-src 'self' 'unsafe-inline'"
```

</td>
</tr>
</tbody>
</table>

---

## Complete minimal example

<table>
<thead>
<tr>
<th>TOML</th>
<th>YAML</th>
</tr>
</thead>
<tbody>
<tr>
<td valign="top">

```toml
preserve_host = false

[listen]
addrs = ["0.0.0.0:8080"]

[[backends]]
address = "localhost:3000"

# A host-less domain is the catch-all: it matches any host (plain HTTP here).
# Routes live under the domain, never at the top level.
[[domains]]

[[domains.routes]]
prefix = "/"
backend = "localhost:3000"
```

</td>
<td valign="top">

```yaml
preserve_host: false

listen:
  addrs:
    - "0.0.0.0:8080"

backends:
  - address: "localhost:3000"

# A host-less domain is the catch-all: it matches any host (plain HTTP here).
# Routes live under the domain, never at the top level.
domains:
  - routes:
      - prefix: "/"
        backend: "localhost:3000"
```

</td>
</tr>
</tbody>
</table>

## Complete production example

See [`examples/config/compose.toml`](examples/config/compose.toml) and [`examples/config/compose.yaml`](examples/config/compose.yaml).
