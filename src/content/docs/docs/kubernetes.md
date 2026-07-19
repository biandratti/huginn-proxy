---
title: Kubernetes
description: How Huginn Proxy and the eBPF agent scale on Kubernetes (not an Ingress controller).
sidebar:
  order: 31
---

> **Huginn Proxy is not a Kubernetes Ingress controller.** There is no Helm chart, CRD, or Ingress class. You run it as a normal workload (Deployment or DaemonSet) with raw manifests.

This setup has been tested and runs in Kubernetes today. The same ideas apply outside Kubernetes: any environment where you can run the proxy as a container or process, plus (for TCP SYN) one eBPF agent per host with shared bpffs (Docker Compose, Nomad, bare metal, etc.).

Images and capabilities: [Artifacts](/huginn-proxy/docs/artifacts/). Capture backends, env vars, and privileges: [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/).

## How it scales

| Workload | Typical shape | Why |
| --- | --- | --- |
| **Proxy** | Deployment or DaemonSet | Serves HTTP/TLS traffic; scale with replicas / HPA, or one instance per node |
| **eBPF agent** | DaemonSet, **one per node** | Linux allows only one XDP/TC program per interface; two agents on the same node fight over the NIC |

TCP SYN fingerprinting needs both on the same node when the proxy reads pinned maps from that node's bpffs. Without TCP SYN (`tcp_enabled = false` / plain image), skip the agent entirely.

## Client IP and port must match the wire

The SYN map is keyed by `(src_ip, src_port)` as seen on the interface the agent attaches to. The proxy looks up the same tuple for the accepted connection. If those do not match, `x-tcp-p0f` misses.

**Behind another proxy (important for TCP SYN):** route that front proxy to the huginn instance on the **same node** where the eBPF agent is capturing. The agent only sees SYNs on its node; if traffic lands on a different node, there is nothing to correlate. That front proxy also needs the right settings so huginn sees the real client endpoint (typically [PROXY protocol](/huginn-proxy/docs/listen/#proxy-protocol) plus [`security.trusted_proxies`](/huginn-proxy/docs/security/#trusted-proxies)).

Also:

- Prefer CNIs that preserve the real client endpoint toward the pod (overlays that SNAT often break correlation).
- Point the agent's interface / destination filters at the traffic that actually reaches the proxy (see [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/)).
