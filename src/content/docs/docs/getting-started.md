---
title: Getting started
description: What Huginn Proxy is and where to go next. Beta.
sidebar:
  order: 1
  badge:
    text: Beta
    variant: caution
---

Huginn Proxy is a reverse proxy built on [Tokio](https://tokio.rs), [Hyper](https://hyper.rs), and [Rustls](https://github.com/rustls/rustls). It passively fingerprints clients (TLS JA4, HTTP/2 Akamai, optional TCP SYN via eBPF) and injects trusted `x-huginn-net-*` headers for backends. Fingerprinting primitives come from [Huginn Net](https://github.com/biandratti/huginn-net). TCP SYN fingerprinting is implemented via an XDP eBPF program using [Aya](https://aya-rs.dev). 

Inspired by production-grade proxies like [Pingora](https://github.com/cloudflare/pingora), [Sozu](https://github.com/sozu-proxy/sozu), and [rust-rpxy](https://github.com/junkurihara/rust-rpxy).

## Prerequisites

- Obtain a binary or image: use the [`master`](https://github.com/biandratti/huginn-proxy) branch in the repository, or follow [Deployment](/huginn-proxy/docs/deployment/) for containers and images.
- Linux (kernel ≥ 5.11) is required for TCP SYN / eBPF fingerprinting; TLS and HTTP/2 fingerprints work on other platforms when eBPF is disabled.
