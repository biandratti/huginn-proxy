# Dockerfile for huginn-ebpf-agent.
# Loads the XDP program, pins BPF maps, and waits for SIGTERM.
#
# Build:
#   docker build -f docker/ebpf-agent.Dockerfile .

# ── builder ─────────────────────────────────────────────────────
FROM rust:1.97.1-slim@sha256:754a8924e308fb20a327febeda1a07053a2b0fd7474b5ac1cc460a6d33ab18f3 AS builder
# bpf-linker uses aya-rustc-llvm-proxy which needs LLVM shared libs from
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly --component rust-src
RUN cargo +nightly install bpf-linker --locked
WORKDIR /app
COPY . .
RUN cargo build --release -p huginn-ebpf-agent

# ── runtime ─────────────────────────────────────────────────────
# debian:trixie-slim — matches rust:1.94.1-slim base (Debian 13, glibc 2.38+).
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
LABEL org.opencontainers.image.description="eBPF XDP agent for huginn-proxy — loads XDP program and pins BPF maps"
COPY --from=builder /app/target/release/huginn-ebpf-agent /usr/local/bin/huginn-ebpf-agent
RUN apt-get update -q && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && chmod 555 /usr/local/bin/huginn-ebpf-agent \
    && rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg
# Runs as root: bpffs (/sys/fs/bpf) is owned by root and BPF syscalls
# require CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON. The agent has no open
# ports, so the attack surface is the same regardless of UID.
CMD ["/usr/local/bin/huginn-ebpf-agent"]
