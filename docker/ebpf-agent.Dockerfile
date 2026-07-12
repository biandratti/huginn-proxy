# Dockerfile for huginn-ebpf-agent.
# Loads the XDP program, pins BPF maps, and waits for SIGTERM.
#
# Build:
#   docker build -f docker/ebpf-agent.Dockerfile .

# ── builder ─────────────────────────────────────────────────────
FROM rust:1.97.0-slim@sha256:14c4fe50ea427dc42381a1a09a9a839c1d2346a2e508cd491bf02c659dbc0ed7 AS builder
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
# debian:trixie-slim - matches rust:1.94.1-slim base (Debian 13, glibc 2.38+).
FROM debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2
LABEL org.opencontainers.image.description="eBPF XDP agent for huginn-proxy - loads XDP program and pins BPF maps"
COPY --from=builder /app/target/release/huginn-ebpf-agent /usr/local/bin/huginn-ebpf-agent
RUN apt-get update -q && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && chmod 555 /usr/local/bin/huginn-ebpf-agent \
    && rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg
# Runs as root: bpffs (/sys/fs/bpf) is owned by root and BPF syscalls
# require CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON. The agent has no open
# ports, so the attack surface is the same regardless of UID.
CMD ["/usr/local/bin/huginn-ebpf-agent"]
