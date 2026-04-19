---
title: How it works
description: Request path, proxy-only vs proxy+agent, fingerprint timing, trust boundary. Beta.
sidebar:
  order: 3
---

Traffic enters the proxy listener (plain or TLS). The first matching **route** wins. [IP filtering](/huginn-proxy/docs/ip-filtering/) and [rate limiting](/huginn-proxy/docs/rate-limiting/) run before forwarding. Fingerprints are derived from the **client→proxy** side of the connection; the proxy then injects **trusted** headers so backends do not rely on spoofable client fields.

## With or without the eBPF agent

You can run **only the proxy** or **the proxy plus the eBPF agent** — they are different operational setups (Compose files and images are not interchangeable). Details: [Containers](/huginn-proxy/docs/containers/).

- **Proxy alone** (typical “plain” image / single service): TLS and HTTP/2 are terminated in-process; **JA4** and **HTTP/2 (Akamai)** headers are produced here when enabled. There is **no** TCP SYN capture — no `x-huginn-net-tcp` from the kernel path.
- **Proxy + agent**: a **sidecar** loads XDP, pins maps, and records SYNs; the proxy **reads** those maps and adds **`x-huginn-net-tcp`**. Needs Linux (e.g. kernel ≥ 5.11), bpffs, and the extra privileges described in [eBPF TCP setup](/huginn-proxy/docs/ebpf-setup/).

JA4 and Akamai always come from the **proxy process**; only the SYN fingerprint depends on the **agent**.

## Fingerprint timing

- **TLS (JA4):** Computed from the ClientHello; in typical use, **once per TLS session** and reused for requests on that session.
- **HTTP/2 (Akamai):** From HTTP/2 SETTINGS / control frames on that connection.
- **TCP SYN:** From the initial SYN when eBPF is enabled; applies to the TCP connection, not each HTTP request on keep-alive.

## Trust boundary

The proxy **overrides** client-supplied `X-Forwarded-*` values. Treat `x-huginn-net-*` as produced by the proxy, not the client.
