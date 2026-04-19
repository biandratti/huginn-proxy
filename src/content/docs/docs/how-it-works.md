---
title: How it works
description: Where fingerprints attach and the trust boundary. Beta.
sidebar:
  order: 3
---

Traffic enters the proxy listener (plain or TLS). The first matching **route** wins. Security policies ([IP filtering](/huginn-proxy/docs/ip-filtering/), rate limits) run before forwarding. Fingerprints are derived from the **client→proxy** side of the connection; the proxy then injects **trusted** headers so backends do not rely on spoofable client fields.

## Fingerprint timing

- **TLS (JA4):** Computed from the ClientHello; in typical use, **once per TLS session** and reused for requests on that session.
- **HTTP/2 (Akamai):** From HTTP/2 SETTINGS / control frames on that connection.
- **TCP SYN:** From the initial SYN when eBPF is enabled; applies to the TCP connection, not each HTTP request on keep-alive.

## Trust boundary

The proxy **overrides** client-supplied `X-Forwarded-*` values. Treat `x-huginn-net-*` as produced by the proxy, not the client.
