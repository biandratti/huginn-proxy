---
title: Documentation
description: Huginn Proxy documentation index. Beta software.
sidebar:
  order: 0
---

Huginn Proxy sits in front of your services and enriches every request with
TLS (JA4), HTTP/2 (Akamai) and TCP SYN fingerprints, without touching your
application code.

Its focus is **fingerprint collection**, **security** (header control, TLS policy, rate limiting), and **performance** (async Rust, connection pooling). It is not trying to be a general-purpose proxy: some features common in Nginx or Traefik are out of scope or not yet implemented. If you need passive client fingerprinting as a first-class feature, this is the tool for you.

This site tracks the **beta** line; verify the [GitHub releases](https://github.com/biandratti/huginn-proxy/releases) for the version you run.

**New here?** Start with [Getting started](/huginn-proxy/docs/getting-started/), then skim
[How it works](/huginn-proxy/docs/how-it-works/) to understand the request pipeline before
diving into configuration.

**Coming from another proxy?** Jump straight to [Quick example](/huginn-proxy/docs/quick-example/)
for a minimal working setup, or [Deployment](/huginn-proxy/docs/deployment/) if you already know
what you want.
