# Dockerfile for huginn-ebpf-agent.
# Loads the XDP program, pins BPF maps, and waits for SIGTERM.
#
# Build:
#   docker build -f docker/ebpf-agent.Dockerfile .

# ── builder ─────────────────────────────────────────────────────
# rust:1.85-slim (amd64)
FROM rust:1.85-slim@sha256:3490aa77d179a59d67e94239cca96dd84030b564470859200f535b942bdffedf AS builder
# bpf-linker uses aya-rustc-llvm-proxy which needs LLVM shared libs from
# the rustc distribution. glibc-based image required (Alpine/musl won't work).
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly --component rust-src
RUN cargo +nightly install bpf-linker --locked
WORKDIR /app
COPY . .
RUN cargo build --release -p huginn-ebpf-agent

# ── runtime ─────────────────────────────────────────────────────
# debian:bookworm-slim (bookworm-20260202-slim, amd64)
FROM debian:bookworm-slim@sha256:74a21da88cf4b2e8fde34558376153c5cd80b00ca81da2e659387e76524edc73
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
