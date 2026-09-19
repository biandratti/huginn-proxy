# Dockerfile for huginn-ebpf-agent.
# Loads the XDP program, pins BPF maps, and waits for SIGTERM.
#
# Build:
#   docker build -f docker/ebpf-agent.Dockerfile .

# ── builder ─────────────────────────────────────────────────────
FROM rust:1.98.1-slim@sha256:f47a8de237dcbb0b0ce1099901e60a89728e3d51f24e664b40e947171538ade7 AS builder
# bpf-linker 0.11+ needs a matching LLVM when built from source; install the prebuilt binary instead.
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly --component rust-src
ARG TARGETARCH
ADD https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz /tmp/cargo-binstall-amd64.tgz
ADD https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-aarch64-unknown-linux-musl.tgz /tmp/cargo-binstall-arm64.tgz
RUN tar -xzf /tmp/cargo-binstall-${TARGETARCH}.tgz -C /usr/local/cargo/bin cargo-binstall \
    && rm /tmp/cargo-binstall-*.tgz \
    && cargo binstall bpf-linker --no-confirm
WORKDIR /app
COPY . .
RUN rustc --edition=2024 -O docker/healthcheck.rs -o /healthcheck
RUN cargo build --release -p huginn-ebpf-agent

# ── runtime ─────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian13:latest@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750
LABEL org.opencontainers.image.description="eBPF XDP agent for huginn-proxy — loads XDP program and pins BPF maps"
COPY --from=builder /app/target/release/huginn-ebpf-agent /usr/local/bin/huginn-ebpf-agent
COPY --from=builder /healthcheck /usr/local/bin/healthcheck
# Runs as root: bpffs (/sys/fs/bpf) is owned by root and BPF syscalls
# require CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON. The agent has no open
# ports, so the attack surface is the same regardless of UID.
USER 0
CMD ["/usr/local/bin/huginn-ebpf-agent"]
