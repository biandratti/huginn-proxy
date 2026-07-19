---
title: Configuration overview
description: Single config file in TOML or YAML, strict validation, effective config, reload behavior, and links to each section.
sidebar:
  order: 1
---

Configuration is read from a **single file** in **TOML** or **YAML**. The format is chosen from the path’s extension: `.yaml` / `.yml` → YAML; `.toml` and anything else (including a missing extension) → TOML. Pass the file path as the positional `CONFIG` argument or via `HUGINN_CONFIG_PATH`:

```bash
huginn-proxy config.toml
huginn-proxy config.yaml
HUGINN_CONFIG_PATH=config.yaml huginn-proxy
```

Validate a config file without starting the proxy:

```bash
huginn-proxy --validate config.toml
huginn-proxy --validate config.yaml
```

Print the validated, **effective** configuration as deterministic JSON (implies `--validate`, then exits):

```bash
huginn-proxy --print-effective-config config.toml
huginn-proxy --validate --print-effective-config config.yaml
```

Includes defaults, normalizations, and fallbacks. Header values and CSP policy are replaced with `<redacted>`; certificate/key/CA paths appear only as configured/not-configured booleans. Diagnostics go to stderr so stdout stays valid JSON for `jq` or CI.

**Strict keys:** unknown or misplaced keys are rejected at every nesting level during startup, `--validate`, and hot reload (they are never silently ignored). This catches typos and YAML indentation mistakes; a failed reload keeps the currently active config.

**Hot reload:** dynamic sections update on `SIGHUP` or a file-watcher trigger without dropping connections. Static sections require a process restart. Changes are logged as a warning and ignored. See the [SETTINGS.md](https://github.com/biandratti/huginn-proxy/blob/master/SETTINGS.md) reference on GitHub for the static/dynamic split per section.

## Environment variables

These apply to the **`huginn-proxy`** process. They do **not** change how TOML vs YAML is detected: that is always from the **config file path** you pass (positional argument or `HUGINN_CONFIG_PATH`): extension `.yaml` / `.yml` → YAML, `.toml` or other → TOML.

| Variable | Role |
| --- | --- |
| `HUGINN_CONFIG_PATH` | Path to the config file when you do **not** pass it as the sole CLI argument (equivalent to `huginn-proxy /path/to/config`). |
| `HUGINN_WATCH` | Set to `true` to enable a **file watcher** so config (and TLS PEMs via config reload) can refresh without sending `SIGHUP`. |
| `HUGINN_WATCH_DELAY_SECS` | Debounce delay in **seconds** after a file change before reload (avoids thrashing on editors that rewrite often). Default `60`. |
| `RUST_LOG` | Overrides log filtering at the Rust tracing layer; can override `[logging].level`. See [Logging](/huginn-proxy/docs/logging/). |

**eBPF (TCP SYN path):** when the proxy uses pinned BPF maps, it reads **`HUGINN_EBPF_PIN_PATH`** (must match the agent) and optionally **`HUGINN_EBPF_RECONNECT_POLL_SECS`**. Map capacity (`HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`) is **agent-only**: the proxy reads it from the pinned `syn_meta` map. Capture backend (`HUGINN_EBPF_CAPTURE`: `xdp-native` / `xdp-skb` / `tc`) is **agent-only**. See [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/#environment-variables).

Canonical field tables and copy-paste snippets: **[SETTINGS.md](https://github.com/biandratti/huginn-proxy/blob/master/SETTINGS.md)** (same content as the shipped reference in the repo).

Use the pages below for narrative, behavior, and examples alongside the reference.

## Top-level keys

Rough split: **static** blocks need a process restart to take effect; **dynamic** blocks reload on `SIGHUP` or the config file watcher (see [SETTINGS.md](https://github.com/biandratti/huginn-proxy/blob/master/SETTINGS.md) for edge cases).

### Static (restart required)

| Key | Page / notes |
| --- | --- |
| `[listen]` | [Listen](/huginn-proxy/docs/listen/) (including `proxy_protocol`) |
| `[tls]` | [TLS](/huginn-proxy/docs/tls/) (transport options only; cert/key paths are per domain) |
| `[fingerprint]` | [Fingerprinting](/huginn-proxy/docs/fingerprinting/) |
| `[timeout]` | [Timeout](/huginn-proxy/docs/timeout/) |
| `[logging]` | [Logging](/huginn-proxy/docs/logging/) |
| `[telemetry]` | [Telemetry](/huginn-proxy/docs/telemetry/) |

### Dynamic (hot-reloadable)

| Key | Page / notes |
| --- | --- |
| `preserve_host` | Top-level bool: [Routes](/huginn-proxy/docs/routes/) (forwarding `Host` upstream) |
| `[[backends]]` | [Backends](/huginn-proxy/docs/backends/) |
| `[[domains]]` | [Routes](/huginn-proxy/docs/routes/) (hostname matching, TLS certs, nested routes) |
| `[security.trusted_proxies]` | [Security](/huginn-proxy/docs/security/) (global CIDR list for XFF / PROXY client-IP resolution) |
| `[security.ip_filter]` | [IP filtering](/huginn-proxy/docs/ip-filtering/) |
| `[security.rate_limit]` | [Rate limiting](/huginn-proxy/docs/rate-limiting/) |
| `[security.headers]` | [Security](/huginn-proxy/docs/security/) (HSTS, CSP, custom: reloadable) |
| `[headers]` | [Headers](/huginn-proxy/docs/headers/) |
| `[backend_pool]` | [Backends](/huginn-proxy/docs/backends/#backend-pool) |

**`[security]`** also includes **`max_connections`** ([Security](/huginn-proxy/docs/security/)), which is **static** (restart required). Treat **`[security]`** as mixed; use the pages above for each subsection.

## Scope and override summary

Security policies and headers can be set at three scopes (**global**, **domain**, and **route**), and each policy has its own override semantics:

| Policy | Global | Domain | Route | Semantics |
| --- | --- | --- | --- | --- |
| `ip_filter` | yes | yes | yes | Whole-block replace |
| `rate_limit` | yes | yes | yes | Whole-block replace |
| `security.headers` (HSTS, CSP, custom) | yes | yes | yes | Whole-block replace |
| `[headers]` (add / remove) | yes | yes | yes | Additive cascade |
| `fingerprinting` | no | yes | yes | Route, domain, or default true |
| `trusted_proxies` | yes | no | no | Global only |
| `max_connections` | yes | no | no | Global only (static) |

**Whole-block replace:** the most specific scope that defines a block wins entirely. A partial override drops the parent's other keys. For example, a route `rate_limit` with only `requests_per_second` and no `enabled = true` **disables** rate limiting for that route. Re-state every key you need.

**Additive cascade:** global, domain, and route headers accumulate in order; for a given header name the most specific scope wins.

The proxy logs a `WARN` at load and on every hot reload when an override drops a parent-enabled protection.

See [Security](/huginn-proxy/docs/security/) and [Rate limiting](/huginn-proxy/docs/rate-limiting/) for examples.

## Examples (repository only)

Full config samples are **not** copied into this site: they would drift from the repo and are tedious to keep in sync. Use the checked-in files as the source of truth:

- **Smallest end-to-end file:** the “Complete minimal example” in [SETTINGS.md](https://github.com/biandratti/huginn-proxy/blob/master/SETTINGS.md) (TOML and YAML at the bottom of that document).
- **Full-featured reference** (listen, TLS, routes, headers, fingerprinting, security, telemetry, etc.): [`examples/config/compose.yaml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/config/compose.yaml) and [`compose.toml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/config/compose.toml) in the same folder.

## Related

- [How it works](/huginn-proxy/docs/how-it-works/): request path through the proxy
- [Quick start](/huginn-proxy/docs/quick-example/): first request end-to-end
