---
title: Kubernetes
description: Deploy Huginn Proxy and the eBPF agent on Kubernetes (DaemonSet + Deployment).
sidebar:
  order: 31
---

Split responsibilities: the **eBPF agent** loads a capture program (XDP or TC) and pins maps; the **proxy** opens those maps read-only when TCP SYN fingerprinting is enabled. Environment variables and capabilities are covered in [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/). Published images: [Artifacts](/huginn-proxy/docs/artifacts/).

## eBPF agent (DaemonSet)

Loads the capture program and pins BPF maps (e.g. under `HUGINN_EBPF_PIN_PATH`). Set `HUGINN_EBPF_CAPTURE` to `xdp-native`, `xdp-skb`, or `tc` as needed. Exposes `/metrics` and `/ready` (configure with `HUGINN_EBPF_METRICS_ADDR` / `HUGINN_EBPF_METRICS_PORT`). Use an HTTP readiness probe to `/ready`. If you use **`127.0.0.1`** for `HUGINN_EBPF_METRICS_ADDR` (as below), probes from the **same pod** can hit loopback; if you switch to **`0.0.0.0`**, scrape from outside the pod using the **pod or Service IP** and port, not `127.0.0.1` from another host. See [eBPF setup: Agent metrics bind address](/huginn-proxy/docs/ebpf-setup/#agent-metrics-bind-address).

Example security and mounts:

```yaml
spec:
 hostNetwork: true # capture on the node's real interface
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
 - name: HUGINN_EBPF_CAPTURE
 value: "xdp-native" # or xdp-skb / tc
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

A **Deployment** is the standard choice when the proxy runs as a centralized service (one or more replicas, behind a Service/LoadBalancer). Use it when TLS and HTTP/2 fingerprinting are enough and you do **not** need TCP SYN fingerprinting, or when the BPF maps are accessible via a shared bpffs volume.

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

## Proxy (DaemonSet)

The following example uses a **DaemonSet**, though a Deployment works equally well depending on your setup.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
 name: huginn-proxy
spec:
 selector:
 matchLabels:
 app: huginn-proxy
 template:
 metadata:
 labels:
 app: huginn-proxy
 spec:
 hostNetwork: true # share the node network namespace; proxy binds on the node IP
 containers:
 - name: proxy
 image: ghcr.io/biandratti/huginn-proxy:latest
 securityContext:
 capabilities:
 add: [BPF]
 seccompProfile:
 type: RuntimeDefault
 ports:
 - containerPort: 7000
 hostPort: 7000 # one proxy instance per node, bound directly on the node IP
 - containerPort: 9090
 hostPort: 9090 # observability
 env:
 - name: HUGINN_EBPF_PIN_PATH
 value: "/sys/fs/bpf/huginn"
 volumeMounts:
 - name: config
 mountPath: /config
 readOnly: true
 - name: bpffs
 mountPath: /sys/fs/bpf
 readOnly: true
 readinessProbe:
 httpGet:
 path: /ready
 port: 9090
 initialDelaySeconds: 5
 periodSeconds: 5
 livenessProbe:
 httpGet:
 path: /live
 port: 9090
 initialDelaySeconds: 10
 periodSeconds: 10
 volumes:
 - name: config
 configMap:
 name: huginn-proxy-config
 - name: bpffs
 hostPath:
 path: /sys/fs/bpf
 type: Directory
```

`HUGINN_EBPF_PIN_PATH` must match the agent’s value. Because both DaemonSets land on the same node, the pinned maps are always reachable.

## Docker Compose vs Kubernetes

| | Docker Compose | Kubernetes |
| --- | --- | --- |
| bpffs | Docker named volume (`type: bpf`) | `hostPath: /sys/fs/bpf` (often already mounted) |
| Agent network | `network_mode: "service:proxy"` | `hostNetwork: true` (typical for capture on the node NIC) |
| AppArmor | `apparmor:unconfined` (some hosts) | Usually handled via Pod Security |
| Proxy scaling | single stack per compose | Deployment + HPA |

## Health check endpoints

**Proxy** (observability server): `/health`, `/ready`, `/live`, `/metrics`.

**eBPF agent:** `/health`, `/ready` (200 when map pins exist under `HUGINN_EBPF_PIN_PATH`), `/live`, `/metrics`.

## Production notes

- **CNI / SNAT:** The SYN map is keyed by source IP and port as seen on the wire. CNIs that hide the original tuple can break correlation; see [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/) § Kubernetes networking.
- TLS material: mount read-only; rotate by replacing PEMs then triggering a **config reload** (SIGHUP or touch the config file with `HUGINN_WATCH`). See [TLS certificate rotation](/huginn-proxy/docs/tls/#certificate-rotation).
