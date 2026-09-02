# Lifecycle

How the proxy starts, serves, and stops, with and without the eBPF agent.
Tuning and kernel requirements live in [EBPF-SETUP.md](EBPF-SETUP.md); endpoint payloads in [TELEMETRY.md](TELEMETRY.md).

## What the lifecycle is for

- **Serve every request that was accepted.** Shutdown fails `/ready` first and keeps accepting for
  `drain_delay_secs`, so the load balancer stops sending traffic before the listen socket closes.
- **Do not lose TCP signatures to a restart.** The capture `bpf_link` is pinned, so a new agent
  replaces the program in place instead of detaching it. SYNs keep landing in the maps even while
  no agent process is running.
- **Always read the map that is being written.** The proxy holds file descriptors to specific
  kernel map objects, not to paths. Reusing the pins keeps those ids stable across agent restarts;
  when they do change, the watcher notices and swaps the whole probe.
- **Report readiness honestly.** A node that cannot produce `x-tcp-p0f` answers 503 instead of
  quietly serving requests without the header.
- **Keep the two processes independent.** Agent and proxy start and stop in any order, and neither
  one takes the other down.

## Without eBPF

One process. TLS (JA4) and HTTP/2 (Akamai) fingerprints only.

```text
                  SIGTERM/SIGINT              drain_delay_secs
                        │                     (2nd signal skips)
  start ─▶ bind ─▶ serving ─▶ Draining ────────────▶ Stopping ─▶ exit
                                                        │
                                    close listeners, GOAWAY, wait_for_drain
```

| Phase    | `/ready`               | Accepting |
|----------|------------------------|-----------|
| start    | 503 `proxy_starting`   | no        |
| serving  | 200                    | yes       |
| Draining | 503 `proxy_draining`   | **yes**   |
| Stopping | 503 `proxy_draining`   | no        |

`Draining` fails the probe while still accepting, so the load balancer pulls the node before the
socket closes. It is terminal: nothing flips `/ready` back to 200.

## With eBPF

Two processes, decoupled through bpffs. The proxy never links against the agent; they only share
pinned objects under `/sys/fs/bpf/huginn`.

```text
┌─ huginn-ebpf-agent ── DaemonSet, one per node ──────────────┐
│  attach XDP or TC                                           │
│  pin maps   {pin}/tcp_syn_map_v4, tcp_syn_map_v6, ...       │
│  pin link   {pin}/capture_link       (TCX / XDP fd-link)    │
│  publish    capture_state{boot_id, generation, lifecycle}   │
│  heartbeat  generation += 1                                 │
└────────────────────────────┬────────────────────────────────┘
                             │  bpffs
┌────────────────────────────▼────────────────────────────────┐
│  huginn-proxy --features ebpf-tcp                           │
│  ebpf-watcher, every HUGINN_EBPF_CAPTURE_POLL_SECS:         │
│    open pinned maps ──▶ syn_probe(peer) ──▶ x-tcp-p0f       │
│    read capture_state ──▶ gate                              │
│                                                             │
│  /ready = listeners up AND gate                             │
└─────────────────────────────────────────────────────────────┘
```

The proxy binds without waiting for the agent, holds its own map file descriptors, and never
crashes when the agent dies. A missed lookup is a missing `x-tcp-p0f` header, not a failed request.

### The gate

`/ready` priority: `proxy_draining`, then `proxy_starting`, then the gate.

| `capture_state`               | Link pin | Gate     | `/ready`               |
|-------------------------------|----------|----------|------------------------|
| absent, or `boot_id = 0`      | any      | Absent   | 503 `capture_absent`   |
| `lifecycle = draining`        | any      | Draining | 503 `capture_draining` |
| capturing                     | exists   | Ready    | 200                    |
| capturing, generation frozen  | none     | Detached | 503 `capture_detached` |
| capturing, generation moving  | none     | Ready    | 200                    |

A pinned link outranks the heartbeat: the program is attached whether or not the agent is alive to
tick. The frozen-generation rows only happen on netlink, which has no pin. All three
`capture_*` reasons collapse to `NOCAPTURE` in text mode.

### Agent

```text
  start ─▶ attach ─▶ pin maps + link ─▶ capture_state = capturing(boot_id, 1)
        ─▶ /ready 200 ─▶ heartbeat
                            │ SIGTERM
                            ▼
                     lifecycle = draining       agent /ready 503
                            │                   capture still attached
                            │ HUGINN_EBPF_DRAIN_DELAY_SECS
                            ▼
                     drop probe                 map and link pins stay behind
```

Draining is terminal here too. `boot_id` guards the writes: a dying agent that no longer owns the
pin leaves `capture_state` alone instead of stomping its replacement.

### Restarts

| Event                            | Capture                        | Proxy `/ready`                            |
|----------------------------------|--------------------------------|-------------------------------------------|
| Agent restart, link pinned       | never stops                    | blips 503 `capture_draining`, back to 200 |
| Agent restart, netlink           | gap until the new agent attaches | 503 `capture_detached` after `HUGINN_EBPF_CAPTURE_STALE_TICKS` |
| Agent crash, no SIGTERM, pinned  | never stops                    | stays 200                                 |
| Agent stopped for good           | pinned keeps running, netlink stops | 503 `capture_draining`               |
| Proxy restart                    | unaffected                     | resolves on the first watcher tick        |

Upgrade the agent first, then the proxy: a new proxy against an agent too old to publish
`capture_state` sits at `capture_absent`.
