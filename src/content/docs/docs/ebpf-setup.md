---
title: eBPF TCP setup
description: XDP or TC capture agent, pinned maps, attach modes, and kernel requirements for TCP SYN fingerprints.
sidebar:
  order: 32
---

TCP SYN fingerprinting uses an eBPF program (**XDP** or **TC clsact**) loaded by **`huginn-ebpf-agent`**. The agent pins BPF maps under **bpffs** (for example under `HUGINN_EBPF_PIN_PATH`). **Huginn Proxy** opens those maps read-only and emits `x-tcp-p0f`. Both backends share the same maps; the proxy does not care which hook is attached.

Full reference (map layout, sizing formula, manifests): [EBPF-SETUP.md](https://github.com/biandratti/huginn-proxy/blob/master/EBPF-SETUP.md).

## Architecture

Two processes cooperate:

1. **eBPF agent** (`huginn-ebpf-agent`): loads the capture program (XDP or TC), attaches it to the interface, pins maps, exposes metrics, stays running. Opens no traffic ports.
2. **Proxy** (`huginn-proxy`): accepts connections, looks up `(src_ip, src_port)` in the map, formats the p0f-style signature.

## Preconditions

- **Kernel ≥ 5.11** (`CAP_BPF`-based loading).
- **bpffs** mounted at `/sys/fs/bpf` (Compose uses a `bpf` volume; on bare metal ensure the mount exists).
- **One agent per node / interface.** A second agent is **not** always a clean failure: XDP attach fails with `EBUSY`, but `tc` can leave **both** programs attached and silently double-count `syn_captured_*`. Nothing errors and nothing logs, so a duplicated agent looks healthy. Deploy as a DaemonSet (K8s) or with `network_mode: "service:proxy"` (Compose).

## Attach mechanism (`capture_mode`)

The agent picks the attach mechanism at load time from the running kernel, then logs it and exports it on `huginn_ebpf_capture_info` (`capture_mode`, `link_pinned`). This decides whether an **agent restart is hitless**:

| Backend | Kernel | `capture_mode` | Pinned `bpf_link` | Agent restart |
| --- | --- | --- | --- | --- |
| `tc` | ≥ 6.6 | `tcx` | yes | hitless; the new agent replaces the program on the same link |
| `tc` | < 6.6 | `netlink` | no (warns at start) | detaches; fresh captures pause until the new agent attaches |
| `xdp-*` | kernel accepts `bpf_link_create` (typically ≥ 5.9) | — | yes | hitless |
| `xdp-*` | netlink fallback | — | no (warns) | detaches |

There is **no `tcx` value** of `HUGINN_EBPF_CAPTURE`; it is chosen for you. Do not assume a rollout is hitless until `link_pinned="true"`.

## Capabilities

| Component | Typical needs |
| --- | --- |
| **eBPF agent** | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (or root); often **seccomp/apparmor unconfined** so `bpf()` and bpffs directory creation succeed in containers. |
| **Proxy** | **`CAP_BPF`** only, granted at runtime. It just **opens** pinned maps: no `setcap`, no unconfined profiles. |

## Environment variables

### Agent

| Variable | Role |
| --- | --- |
| `HUGINN_EBPF_INTERFACE` | NIC to attach to (in Docker Compose with `network_mode: service:proxy`, this is the **proxy** container’s `eth0`). |
| `HUGINN_EBPF_DST_PORT` | Listener port to filter toward (the proxy’s TLS/HTTP port, e.g. `7000`). |
| `HUGINN_EBPF_DST_IP_V4` | IPv4 destination filter (`0.0.0.0` = no filter). |
| `HUGINN_EBPF_DST_IP_V6` | IPv6 counterpart (`::` = no filter; quote in YAML if needed). |
| `HUGINN_EBPF_PIN_PATH` | Directory under bpffs where maps are pinned (e.g. `/sys/fs/bpf/huginn`). **Same** on proxy. |
| `HUGINN_EBPF_LINK_PIN_PATH` | Pin path for the capture `bpf_link` (default `{PIN_PATH}/capture_link`). Left in place on SIGTERM so the next agent can replace the program atomically. Unused on netlink attaches. The proxy gate `stat()`s it as proof of attach. |
| `HUGINN_EBPF_DRAIN_DELAY_SECS` | Agent phase 1: publish `draining` and wait before detaching. |
| `HUGINN_EBPF_HEARTBEAT_SECS` | How often userspace bumps `capture_state.generation` (positive integer). Used on the netlink path, where there is no link pin. |
| `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` | LRU map capacity. **Agent-only**: published into `syn_meta` for the proxy; do **not** set this on the proxy. |
| `HUGINN_EBPF_CAPTURE` | Capture backend: `xdp-native` (default), `xdp-skb`, or `tc`. See [Choosing a capture backend](#choosing-a-capture-backend). |
| `HUGINN_EBPF_LOG_LEVEL` | In-kernel datapath log level: `off` (default), `error`, `warn`, `info`, `debug`, `trace`. The level gate runs in-kernel, so `off` is zero-cost on the hot path. Diagnostics only. |
| `HUGINN_EBPF_METRICS_ADDR` / `HUGINN_EBPF_METRICS_PORT` | Where the **agent** binds `/metrics`, `/health`, `/ready`, `/live`. |
| `HUGINN_EBPF_HEALTH_FORMAT` | `json` (default) or `text` for those health bodies. |
| `HUGINN_EBPF_RATE_LIMIT_ENABLED` | Optional in-kernel per-source SYN rate limiter (`false` by default). Over-limit SYNs are **not captured** (packet still forwarded). |
| `HUGINN_EBPF_RATE_LIMIT_BURST` | Max SYNs per window per source before skipping capture (`1..=65534`, default `2000`). Counted **per CPU**; size against `SYN_MAP_MAX_ENTRIES`, not the proxy’s `[security.rate_limit]`. |
| `HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS` | Sliding window length in seconds (`1..=3600`, default `1`). |

> A bad agent variable **stops the agent**; the proxy then sits at 503 `capture_absent`, so check the agent log first. The default `burst = 2000` is not a sized value: compute yours with [Sizing the SYN rate limiter](https://github.com/biandratti/huginn-proxy/blob/master/EBPF-SETUP.md#sizing-the-syn-rate-limiter). The limiter shields the capture LRU from one loud source; it is **not** a DoS defense.

### Proxy

| Variable | Role |
| --- | --- |
| `HUGINN_EBPF_PIN_PATH` | Pin directory to read maps from (must match the agent). |
| `HUGINN_EBPF_LINK_PIN_PATH` | Path the capture gate `stat()`s as proof of attach (same default as the agent). |
| `HUGINN_EBPF_CAPTURE_POLL_SECS` | How often the capture gate refreshes (minimum `1`; `0` is a startup error). |
| `HUGINN_EBPF_CAPTURE_STALE_TICKS` | Polls without a `generation` bump before `capture_detached` (**netlink path only**). |
| `HUGINN_EBPF_RECONNECT_POLL_SECS` | Backstop poll for detecting recreated maps (default `5`). `0` disables reconnection but **does not** stop the capture gate. |

Also set `fingerprint.tcp_enabled = true` in config. Full stack layout (Compose, caps, volumes): [`examples/docker-compose.ebpf.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.ebpf.yml) and [`examples/docker-compose.release-ebpf.yml`](https://github.com/biandratti/huginn-proxy/blob/master/examples/docker-compose.release-ebpf.yml).

### Choosing a capture backend

Both hooks live in the same BPF object and share identical maps. Only the kernel hook differs:

- **`xdp-native`**: driver-level XDP. Lowest overhead. Needs NIC driver XDP support.
- **`xdp-skb`**: generic XDP in the kernel stack. Works on veth/loopback/VMs.
- **`tc`**: TC `clsact` **ingress**. GRO-safe; attaches via TCX or netlink depending on the kernel.

> Prefer `tc` over `xdp-skb` when native XDP is not available: generic XDP only sees the first segment of GRO-aggregated packets and drops non-linear skbs. TC runs after GRO and reads the full skb. Capabilities are the same.

### Agent metrics bind address

| `HUGINN_EBPF_METRICS_ADDR` | Listens on | Scrape / curl from |
| --- | --- | --- |
| **`127.0.0.1`** | Loopback in the agent netns only | Same netns, or host `127.0.0.1:$PORT` when the port is published. |
| **`0.0.0.0`** | All interfaces in that netns | Host or pod **IP** (+ port) when scraping **remotely** (not `127.0.0.1` from another machine). |

## Docker Compose specifics

- **`network_mode: "service:proxy"`** on the agent puts the agent in the **proxy’s network namespace**, so the interface name (`eth0`) and destination filter match the traffic the proxy actually receives.
- **`bpffs`** must be mounted into **both** containers at `/sys/fs/bpf` (or adjust paths consistently).
- **Health:** agent `/ready` is attached + required pins + not draining (kubelet only). Proxy `/ready` also requires the capture gate when `fingerprint.tcp_enabled` is on. Roll the **agent image first**, then the proxy.

See [Containers](/huginn-proxy/docs/containers/) for the two Compose layouts (eBPF vs plain) and [Artifacts](/huginn-proxy/docs/artifacts/) for GHCR image names.

## Kubernetes networking

The SYN map is keyed by **source IP and port** as seen on the wire. CNIs that SNAT client traffic toward pods (e.g. Flannel) break the correlation. Most production CNIs (Cilium, AWS VPC CNI, Calico BGP) do not SNAT.

## Runtime lifecycle

- **Startup:** the proxy binds immediately. `/ready` is 503 (`capture_absent`) until the agent publishes `capture_state` with a non-zero `agent_boot_id`; lookups miss until the watcher opens the pins. Start order does not matter.
- **Agent down:** the proxy keeps its own map FDs and does **not** crash; lookups return a miss and `x-tcp-p0f` is omitted. HTTP is never blocked. With a pinned link the program stays on the interface; on netlink it detaches and fresh captures pause.
- **Rollout:** on SIGTERM the agent publishes `draining`, which the gate ranks above a live link pin, so every proxy on the node goes 503 (`capture_draining`) until the next agent publishes `capturing`. **Capture can continue while `/ready` blips.** Use `maxUnavailable: 1`.
- **Maps:** shutdown leaves the map pins and the link pin; the next agent reopens the same kernel IDs. Maps are recreated only when `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` changes (or bpffs is wiped); the proxy then swaps atomically within `HUGINN_EBPF_RECONNECT_POLL_SECS`.

> Deleting the DaemonSet is the same SIGTERM as a rollout: **pins stay**. The program can keep running with no userspace owner until reboot or until a new agent adopts the pin. Uninstalling does not remove the datapath.

## Keep-alives and misses

The SYN is looked up once at accept and reused, so `x-tcp-p0f` is present on **every** keep-alive request, not just the first. A missing header means the SYN was never captured (startup, eviction) or the entry is stale (more than `2 × syn_map_max_entries` SYNs since capture). `force_new_connection = true` opens a new connection to the **backend**; it does not recapture the client SYN.
