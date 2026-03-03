# Architecture

## Modules

**`huginn-proxy`** - Binary. Entry point. Reads config and env vars, initializes the eBPF probe, builds the `SynProbe` closure, and calls `run()`.

**`huginn-proxy-lib`** - Core proxy logic. Platform-agnostic. Handles TCP accept, TLS, HTTP routing, fingerprint header injection, backend forwarding, rate limiting, telemetry, and connection management.

**`huginn-ebpf`** - eBPF loader. Linux-only, gated behind the `ebpf-tcp` feature. Attaches the XDP program, reads `SynRawData` from the BPF map, and exposes `parse_syn()` to turn raw captured data into a `TcpObservation`.

**`huginn-ebpf-xdp`** - XDP kernel program. Compiled with nightly for `bpfel-unknown-none`, embedded into `huginn-ebpf` at build time. Captures TCP SYN packets and writes `SynRawData` into a BPF LRU map keyed by `(src_ip, src_port)`.

**`huginn-ebpf-agent`** - Standalone eBPF agent. Loads the XDP program, pins BPF maps to `/sys/fs/bpf/huginn/`, and stays alive until SIGTERM. Designed to run as a DaemonSet so that the proxy (Deployment) can open pinned maps without `CAP_NET_ADMIN`.

---

## TCP SYN fingerprinting via eBPF/XDP

```
huginn-ebpf-xdp (kernel)          huginn-ebpf                huginn-proxy
───────────────────────────────    ──────────────────────     ──────────────────
SynRawData { window, ip_ttl,       parse_syn(&raw)            match result {
  optlen, options[40],          →    parse_options_raw()   →    Hit(obs) → inject headers
  quirks, ip_olen, tick }             ttl::calculate_ttl()       Miss     → skip
                                      window_size::detect…()     Malformed→ skip
                                   → Option<TcpObservation>  }
```

`huginn-proxy-lib` never imports `huginn-ebpf`. The result crosses the boundary as a single callback:

```rust
pub type SynProbe = Arc<dyn Fn(SocketAddr) -> SynResult + Send + Sync>;
```

`huginn-proxy` provides the implementation; `huginn-proxy-lib` only calls it.
