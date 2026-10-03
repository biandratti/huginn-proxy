# Dockerfile for huginn-ebpf-agent.
# Loads the XDP program, pins BPF maps, and waits for SIGTERM.
#
# Build:
#   docker build -f docker/ebpf-agent.Dockerfile .

# ── builder ─────────────────────────────────────────────────────
FROM rust:1.99.0-slim@sha256:01dd4f9c24801cfc8ba9cf8a5dd6dcca451cd17d1ae73574edc22591de6e6816 AS builder
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
FROM gcr.io/distroless/cc-debian13:latest@sha256:159783207c2cd44c2aa5715961d13c8612368ac9bd450f887e3f08fc8ea461e3
LABEL org.opencontainers.image.description="eBPF XDP agent for huginn-proxy — loads XDP program and pins BPF maps"
COPY --from=builder /app/target/release/huginn-ebpf-agent /usr/local/bin/huginn-ebpf-agent
COPY --from=builder /healthcheck /usr/local/bin/healthcheck
# Runs as root: bpffs (/sys/fs/bpf) is owned by root and BPF syscalls
# require CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON. The agent has no open
# ports, so the attack surface is the same regardless of UID.
USER 0
CMD ["/usr/local/bin/huginn-ebpf-agent"]
