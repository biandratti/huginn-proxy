---
title: Documentation
description: Huginn Proxy documentation index.
sidebar:
  order: 0
---

Huginn Proxy sits in front of your services and enriches every request with
TLS (JA4), HTTP/2 (Akamai) and TCP SYN fingerprints, without touching your
application code.

It collects fingerprints, and it has the security and performance pieces needed to sit in front of a service (header control, TLS policy, rate limiting, connection pooling). It is not a general-purpose proxy. Nginx and Traefik still do things this one does not.

## Live demo

[huginn-proxy.duckdns.org](https://huginn-proxy.duckdns.org/) shows the fingerprints of the browser that opens it. huginn-proxy terminates TLS, collecting and parsing that visit with [huginn-net](https://github.com/biandratti/huginn-net).

Check the [GitHub releases](https://github.com/biandratti/huginn-proxy/releases) for the version you run.

**New here?** Start with [Getting started](/huginn-proxy/docs/getting-started/), then skim
[How it works](/huginn-proxy/docs/how-it-works/) to understand the request pipeline before
diving into [Configuration overview](/huginn-proxy/docs/configuration/).

**Coming from another proxy?** Jump straight to [Quick start](/huginn-proxy/docs/quick-example/)
for a minimal working setup, or [Containers](/huginn-proxy/docs/containers/) if you already know
what you want.
