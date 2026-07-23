# Architecture

## Modules

**`huginn-proxy`** - Binary. Its entry point owns process lifecycle, observability, and shutdown.
Validation output is isolated from runtime startup, while the eBPF integration owns pinned-map
connection retries, construction of the `SynProbe` callback, and automatic pinned-map reconnection
before the binary calls `run()`.

**`huginn-proxy-lib`** - Core proxy logic. Platform-agnostic. Handles TCP accept, TLS, HTTP routing, fingerprint header injection, backend forwarding, rate limiting, telemetry, and connection management. Its config layer provides strict TOML/YAML deserialization and a deterministic, secret-redacted effective configuration view. Its proxy layer separates listener orchestration and per-connection dispatch from PROXY protocol trust, timeout, and effective-client resolution. It owns the TLS acceptor (cipher suites, ALPN, mTLS, session resumption) but delegates certificate material and SNI resolution to `huginn-certs`, wiring the two together in `tls/cert_reload.rs`.

**`huginn-certs`** - Certificate crate. Owns *which certificate to serve* and *how cert material is loaded from disk*, decoupled from the proxy's config and telemetry. Provides `read_certs_and_keys()` + `cert_chain_hash()` (PEM material), `CertEntry` (a config-agnostic cert description), and `DynamicCertResolver` implementing rustls `ResolvesServerCert` for SNI selection (exact → wildcard → catch-all, with `sni_strict` parity to Traefik). `update(&[CertEntry])` swaps the cert map atomically via `ArcSwap` and returns a `CertReloadReport` (loaded/failed labels + chain hashes) so the caller records metrics without the crate depending on `telemetry`. File layout mirrors rpxy's `rpxy-certs` for navigation, but the model is huginn's single-`ServerConfig` resolver, not rpxy's per-SNI `HashMap<SNI, ServerConfig>`.

**`huginn-ebpf-common`** - Shared `no_std` crate for TCP SYN fingerprinting. Defines `SynRawDataV4` / `SynRawDataV6` layout, `quirk_bits` constants, and `make_key(src_ip, src_port)` encoding. Used by both `huginn-ebpf-programs` (kernel) and `huginn-ebpf` (userspace) so map layout and key encoding stay in sync. Optional feature `aya` enables `aya::Pod` for those types in userspace only.

**`huginn-ebpf`** - eBPF loader. Linux-only, gated behind the `ebpf-tcp` feature. Opens pinned BPF maps (or loads the capture program when embedded), reads `SynRawDataV4` / `SynRawDataV6` from the map, and exposes `parse_syn_v4()` / `parse_syn_v6()` to turn raw captured data into a `TcpObservation`. Depends on `huginn-ebpf-common` for types and `quirk_bits`.

**`huginn-ebpf-programs`** - BPF kernel programs. Compiled with nightly for `bpfel-unknown-none`, embedded into `huginn-ebpf` at build time. Ships two hooks in one object that share maps, key encoding, and value layout: `huginn_xdp_syn` (XDP) and `huginn_tc_syn` (TC `clsact` ingress, GRO-safe). Depends on `huginn-ebpf-common` for types, `quirk_bits`, and `make_key`.

**`huginn-ebpf-agent`** - Standalone eBPF agent. Loads the selected capture program (XDP or TC, via `HUGINN_EBPF_CAPTURE`), pins BPF maps to `/sys/fs/bpf/huginn/` via `map_pin_path`, and stays alive until SIGTERM. Pins are left in place on shutdown so the next agent instance reuses the same maps (same kernel IDs, preserved contents); only a capacity change (`HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`) forces recreation. Designed to run as a DaemonSet so that the proxy (Deployment) can open pinned maps without `CAP_NET_ADMIN`.

---

## TCP SYN fingerprinting via eBPF

```
huginn-ebpf-programs (kernel)      huginn-ebpf                      huginn-proxy
───────────────────────────────    ──────────────────────────────   ──────────────────
SynRawDataV4 / SynRawDataV6        parse_syn_v4(&raw) /             match result {
  { window, ip_ttl, optlen,    →     parse_syn_v6(&raw)         →     Hit(obs) → inject headers
    options[40], quirks, tick }        parse_options_raw()              Miss     → skip
  (layout: huginn-ebpf-common)        ttl::calculate_ttl()             Malformed→ skip
                                       window_size::detect…()        }
                                   → Option<TcpObservation>
```

`SynRawDataV4` / `SynRawDataV6` and the map key encoding are defined in **`huginn-ebpf-common`** so kernel and userspace never drift.

`huginn-proxy-lib` never imports `huginn-ebpf`. The result crosses the boundary as a single callback:

```rust
pub type SynProbe = Arc<dyn Fn(SocketAddr) -> SynResult + Send + Sync>;
```

`huginn-proxy` provides the implementation; `huginn-proxy-lib` only calls it.

The capture hook is selectable via `HUGINN_EBPF_CAPTURE` (`xdp-native` | `xdp-skb` | `tc`). The single BPF object embeds both programs sharing the same maps, key encoding, and value layout. `tc` reads via `bpf_skb_load_bytes` (GRO-safe) and returns `TC_ACT_OK`; the proxy reads the same pinned maps regardless of backend. See `EBPF-SETUP.md` for backend selection guidance.

### Process lifecycle and failure isolation

The agent and the proxy are decoupled processes. At startup the proxy retries opening the agent's pinned maps with a fixed backoff, so the two can start in any order. Once connected, the proxy holds its own map file descriptors: an agent crash never crashes the proxy, and lookups degrade to `SynResult::Miss` (the `x-tcp-p0f` header is skipped) rather than blocking or dropping traffic. Because the agent reuses its pinned maps across restarts, a normal restart keeps the same kernel IDs and the proxy needs no reconnection at all. As a backstop, a shutdown-aware background task compares the kernel IDs of the published IPv4/IPv6 pins with the active IDs; when the maps are actually recreated (a capacity change, or a wiped bpffs) the proxy opens a complete new map set and publishes it through `ArcSwap`, so in-flight lookups finish on the previous set and new lookups use the replacement without dropping connections. See `EBPF-SETUP.md` for the polling interval and full lifecycle guidance.

The stale-entry threshold needs the LRU capacity. The agent publishes it once into a family-agnostic `syn_meta` map (a sibling of `syn_counter`); the proxy reads it back rather than being configured with it, so it never drifts and does not depend on which IP family is enabled. The value is pinned, so it survives agent restarts/crashes; a freshly recreated map reads `0` until the agent writes it, which the proxy treats as *not ready* and retries.

### Lifecycle scenarios

Maps live in bpffs independently of both processes. The proxy connects via a startup retry loop and stays current via the backstop watcher, both funnelling through a single `ArcSwap<EbpfProbe>`:

```
startup:   from_pinned() ──Err (pins absent │ MapNotReady)──▶ wait 2s ──┐
               │ Ok                                            ▲         │
               ▼                                               └─────────┘
         ArcSwap<EbpfProbe> ◀── proxy holds its own map FDs (outlive the agent)
               ▲
watcher   every HUGINN_EBPF_RECONNECT_POLL_SECS:
(backstop)   published IDs == active IDs ? ── yes ─▶ keep current maps
                                           └─ no ──▶ from_pinned() ─▶ ArcSwap.store()
```

Only the TCP SYN fingerprint (`x-tcp-p0f`) depends on eBPF. TLS JA4 and HTTP/2 Akamai are extracted in-process from the ClientHello and HTTP/2 frames, so they are unaffected by any agent/eBPF state below.

| Event | Maps in bpffs | Proxy reaction | `x-tcp-p0f` header |
|---|---|---|---|
| Startup, pins absent | — | retry `from_pinned` every 2s | skipped until connected |
| `syn_meta` pinned but unwritten | fresh, capacity `0` | `MapNotReady` → retry | skipped (transient) |
| Agent graceful restart | reused, same IDs | none (IDs unchanged) | uninterrupted |
| Agent crash (SIGKILL) | survive (pinned) + proxy FDs | none; captures continue (program stays attached) | uninterrupted |
| Capacity change / bpffs wipe | recreated, new IDs | watcher reopens, atomic `ArcSwap` swap | in-flight on old set, new lookups on new set |
| Reconnect poll disabled (`=0`) | recreated, new IDs | none until proxy restart | skipped until restart |
