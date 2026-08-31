# Architecture

## Modules

**`huginn-proxy`** - Binary. Its entry point owns process lifecycle, observability, and shutdown.
Validation output is isolated from runtime startup, while the eBPF integration owns the
capture `ReadinessGate`, construction of the `SynProbe` callback, and the watcher that opens
pinned maps (and reconnects them) before the binary calls `run()`.

**`huginn-proxy-lib`** - Core proxy logic. Platform-agnostic. Handles TCP accept, TLS, HTTP routing, fingerprint header injection, backend forwarding, rate limiting, telemetry, and connection management. Its config layer provides strict TOML/YAML deserialization and a deterministic, secret-redacted effective configuration view. Its proxy layer separates listener orchestration and per-connection dispatch from PROXY protocol trust, timeout, and effective-client resolution. It owns the static TLS options (cipher suites, ALPN, `sni_strict`, resumption on/off) and the accept path (`LazyConfigAcceptor` → per-SNI config selection), but delegates the per-SNI `ServerConfig` construction, per-domain mTLS, and certificate material to `huginn-certs`, wiring the two together in `tls/cert_reload.rs`.

**`huginn-certs`** - Certificate crate. Owns *which certificate to serve*, *where cert material comes from*, and *how the per-SNI TLS config is built*, decoupled from the proxy's config and telemetry. Provides `cert_chain_hash()`, a `CryptoSource` trait abstracting the material origin (with `CryptoFileSource` + `read_certs_and_keys()` as the filesystem implementation, including an optional client-CA bundle), `CertEntry` (a config-agnostic cert description pairing an `Arc<dyn CryptoSource>` with its SNI host/label), and `build_server_crypto()` which builds a `ServerCryptoMap`: **one rustls `ServerConfig` per domain**, selected at handshake time by SNI (exact → wildcard → catch-all, with `sni_strict` parity to Traefik). A domain whose material carries client-CA anchors gets its own `WebPkiClientVerifier` (per-domain mTLS); non-mTLS configs share a process-wide stateless ticketer while mTLS configs never resume. The build returns a `CertReloadReport` (loaded/failed labels + chain hashes) so the caller records metrics without the crate depending on `telemetry`. File layout and model mirror rpxy's `rpxy-certs` (per-SNI configs), with huginn's exact → wildcard → catch-all resolution kept on top.

**`huginn-ebpf-common`** - Shared `no_std` crate for TCP SYN fingerprinting. Defines `SynRawDataV4` / `SynRawDataV6` layout, `quirk_bits` constants, and `make_key(src_ip, src_port)` encoding. Used by both `huginn-ebpf-programs` (kernel) and `huginn-ebpf` (userspace) so map layout and key encoding stay in sync. Optional feature `aya` enables `aya::Pod` for those types in userspace only.

**`huginn-ebpf-rate-limit`** - Shared `no_std` crate implementing the per-source SYN rate limiter: a dual-buffer sliding-window Count-Min Sketch (`Sketch`). Used only by `huginn-ebpf-programs` (kernel), which calls `Sketch::observe_over_limit()` on a BPF-map-backed `Sketch` before capturing a SYN, to skip capturing floods from a single source (the packet still passes; it is just not fingerprinted) without letting them saturate the `tcp_syn_map_v4`/`v6` LRU maps. Sources are hashed with a random seed the loader draws per program load and patches into the `syn_rate_seed` global; IPv4 is keyed per address, IPv6 per /64 prefix (see the crate README).

**`huginn-ebpf`** - eBPF loader. Linux-only, gated behind the `ebpf-tcp` feature. Opens pinned BPF maps (or loads the capture program when embedded), reads `SynRawDataV4` / `SynRawDataV6` from the map, and exposes `parse_syn_v4()` / `parse_syn_v6()` to turn raw captured data into a `TcpObservation`. Depends on `huginn-ebpf-common` for types and `quirk_bits`, and on `huginn-ebpf-rate-limit` for the `burst` ceiling `SynRateLimit` validates against.

**`huginn-ebpf-programs`** - BPF kernel programs. Compiled with nightly for `bpfel-unknown-none`, embedded into `huginn-ebpf` at build time. Ships two hooks in one object that share maps, key encoding, and value layout: `huginn_xdp_syn` (XDP) and `huginn_tc_syn` (TC `clsact` ingress, GRO-safe). Depends on `huginn-ebpf-common` for types, `quirk_bits`, and `make_key`, and on `huginn-ebpf-rate-limit` for the SYN rate-limiting `Sketch`.

**`huginn-ebpf-agent`** - Standalone eBPF agent. Loads the selected capture program (XDP or TC, via `HUGINN_EBPF_CAPTURE`), pins BPF maps to `/sys/fs/bpf/huginn/` via `map_pin_path`, and pins the capture `bpf_link` at `{pin_path}/capture_link` when the attach is an fd-link (TCX or XDP fd-link). Map and link pins are left in place on SIGTERM so the next agent reuses the same maps and, when a link pin exists, atomically replaces the program. Designed to run as a DaemonSet so that the proxy (Deployment) can open pinned maps without `CAP_NET_ADMIN`.

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

The capture hook is selectable via `HUGINN_EBPF_CAPTURE` (`xdp-native` | `xdp-skb` | `tc`). The single BPF object embeds both programs sharing the same maps, key encoding, and value layout. `tc` reads via `bpf_skb_load_bytes` (GRO-safe) and returns `TC_ACT_OK`. Effective attach mechanism is logged and exported as `capture_mode` (`tcx` | `netlink` | `xdp-native` | `xdp-skb`); TCX and XDP fd-links are pinned at `{pin_path}/capture_link` so agent restarts replace the program in place. The proxy reads the same pinned maps regardless of backend. See `EBPF-SETUP.md` for backend selection and leftover-datapath notes.

### Process lifecycle and failure isolation

The agent and the proxy are decoupled processes. The proxy binds without waiting for pins: a capture `ReadinessGate` (injected like `SynProbe`, without the library importing eBPF) keeps `/ready` at 503 (`capture_absent`) until the agent publishes `capture_state`. Lookups miss until the watcher opens the maps. Once connected, the proxy holds its own map file descriptors: an agent crash never crashes the proxy. On a pinned `bpf_link`, capture continues across agent death; on netlink, the gate falls through to the `generation` heartbeat. Map reuse across agent restarts keeps kernel IDs stable. As a backstop, the same watcher compares published vs open map IDs on `HUGINN_EBPF_RECONNECT_POLL_SECS` and swaps via `ArcSwap` when they change. See `EBPF-SETUP.md`.

The stale-entry threshold needs the LRU capacity. The agent publishes it once into a family-agnostic `syn_meta` map (a sibling of `syn_counter`); the proxy reads it back rather than being configured with it, so it never drifts and does not depend on which IP family is enabled. The value is pinned, so it survives agent restarts/crashes; a freshly recreated map reads `0` until the agent writes it, which the proxy treats as *not ready* and retries.

### Lifecycle scenarios

Maps live in bpffs independently of both processes. The proxy starts with an empty probe and a capture gate; the watcher fills maps when pins appear:

```
startup:   bind + /live 200; /ready 503 capture_absent until capture_state.boot_id != 0
         ArcSwap<Option<EbpfProbe>>  (None → Miss; Some → lookup)
               ▲
watcher   every HUGINN_EBPF_CAPTURE_POLL_SECS:
           refresh gate (draining → link pin → heartbeat)
           if probe is None: try from_pinned()
           every HUGINN_EBPF_RECONNECT_POLL_SECS (if ≠ 0):
             published IDs == active IDs ? keep : from_pinned() → ArcSwap
```

Only the TCP SYN fingerprint (`x-tcp-p0f`) depends on eBPF. TLS JA4 and HTTP/2 Akamai are extracted in-process from the ClientHello and HTTP/2 frames, so they are unaffected by any agent/eBPF state below.

| Event | Maps in bpffs | Proxy reaction | `x-tcp-p0f` header |
|---|---|---|---|
| Startup, pins absent | — | watcher retries `from_pinned`; `/ready` `capture_absent` | skipped until connected |
| `syn_meta` pinned but unwritten | fresh, capacity `0` | `MapNotReady` → retry | skipped (transient) |
| Agent graceful restart | reused, same IDs; link pin replaced in place when present | none (IDs unchanged) | uninterrupted on pinned-link attaches; brief miss window on netlink |
| Agent crash (SIGKILL) | maps survive (pinned) + proxy FDs; program stays attached iff the link is pinned | none | uninterrupted when `link_pinned`; otherwise fresh captures stop until a new agent attaches |
| Capacity change / bpffs wipe | recreated, new IDs | watcher reopens, atomic `ArcSwap` swap | in-flight on old set, new lookups on new set |
| Reconnect poll disabled (`=0`) | recreated, new IDs | gate still refreshes; maps stay until proxy restart | skipped until restart |
