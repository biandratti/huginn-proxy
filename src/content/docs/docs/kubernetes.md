---
title: Kubernetes
description: Deploy Huginn Proxy and the eBPF agent on Kubernetes (DaemonSet + Deployment). Beta.
sidebar:
  order: 31
---

Split responsibilities: the **eBPF agent** loads XDP and pins maps; the **proxy** opens those maps read-only when TCP SYN fingerprinting is enabled. Environment variables and capabilities are covered in [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/). Published images: [Artifacts](/huginn-proxy/docs/artifacts/).

## eBPF agent (DaemonSet)

Loads XDP and pins BPF maps (e.g. under `HUGINN_EBPF_PIN_PATH`). Exposes `/metrics` and `/ready` (configure with `HUGINN_EBPF_METRICS_ADDR` / `HUGINN_EBPF_METRICS_PORT`). Use an HTTP readiness probe to `/ready`. If you use **`127.0.0.1`** for `HUGINN_EBPF_METRICS_ADDR` (as below), probes from the **same pod** can hit loopback; if you switch to **`0.0.0.0`**, scrape from outside the pod using the **pod or Service IP** and port—not `127.0.0.1` from another host. See [eBPF setup — Agent metrics bind address](/huginn-proxy/docs/ebpf-setup/#agent-metrics-bind-address).

Example security and mounts:

```yaml
spec:
  hostNetwork: true # XDP on the node's real interface
  containers:
    - name: ebpf-agent
      image: ghcr.io/biandratti/huginn-proxy-ebpf-agent:latest
      securityContext:
        capabilities:
          add: [BPF, NET_ADMIN, PERFMON]
        seccompProfile:
          type: Unconfined # bpf() syscall required
      env:
        - name: HUGINN_EBPF_INTERFACE
          value: "eth0"
        - name: HUGINN_EBPF_DST_IP_V4
          value: "0.0.0.0"
        - name: HUGINN_EBPF_DST_PORT
          value: "7000"
        - name: HUGINN_EBPF_PIN_PATH
          value: "/sys/fs/bpf/huginn"
        - name: HUGINN_EBPF_METRICS_ADDR
          value: "127.0.0.1"
        - name: HUGINN_EBPF_METRICS_PORT
          value: "9091"
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
      readinessProbe:
        httpGet:
          path: /ready
          port: 9091
        initialDelaySeconds: 5
        periodSeconds: 5
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: DirectoryOrCreate
```

## Proxy (Deployment)

**With TCP fingerprinting** (`tcp_enabled = true`): requires the DaemonSet above.

```yaml
spec:
  containers:
    - name: proxy
      image: ghcr.io/biandratti/huginn-proxy:latest
      securityContext:
        capabilities:
          add: [BPF]
        seccompProfile:
          type: RuntimeDefault
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
          readOnly: true
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: Directory
```

**Without TCP fingerprinting** (`tcp_enabled = false`): no DaemonSet, no BPF capabilities, no bpffs.

```yaml
spec:
  containers:
    - name: proxy
      image: ghcr.io/biandratti/huginn-proxy-plain:latest
      securityContext:
        seccompProfile:
          type: RuntimeDefault
```

Pin paths and interface names must match between agent configuration and node networking. Readiness should probe the agent’s `/ready` when maps must exist before traffic.

## Docker Compose vs Kubernetes

| | Docker Compose | Kubernetes |
| --- | --- | --- |
| bpffs | Docker named volume (`type: bpf`) | `hostPath: /sys/fs/bpf` (often already mounted) |
| Agent network | `network_mode: "service:proxy"` | `hostNetwork: true` (typical for XDP on NIC) |
| AppArmor | `apparmor:unconfined` (some hosts) | Usually handled via Pod Security |
| Proxy scaling | single stack per compose | Deployment + HPA |

## Health check endpoints

**Proxy** (observability server): `/health`, `/ready`, `/live`, `/metrics`.

**eBPF agent:** `/health`, `/ready` (200 when map pins exist under `HUGINN_EBPF_PIN_PATH`), `/live`, `/metrics`.

## Production notes

- **CNI / SNAT:** The SYN map is keyed by source IP and port as seen on the wire. CNIs that hide the original tuple can break correlation; see [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/) § Kubernetes networking.
- TLS material: mount read-only; align with `watch_delay_secs` for rotation.
