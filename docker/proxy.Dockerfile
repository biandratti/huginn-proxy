# Multi-stage Dockerfile for huginn-proxy.
# Targets:
#   plain  — no eBPF, stable toolchain, no Linux capabilities needed.
#   ebpf   — TCP SYN fingerprinting via pinned BPF maps, needs CAP_BPF at runtime.
#
# Build:
#   docker build --target plain -f docker/proxy.Dockerfile .
#   docker build --target ebpf  -f docker/proxy.Dockerfile .    (or just: docker build -f ...)

# ── builder base ────────────────────────────────────────────────
FROM rust:1.96.0-slim@sha256:3b05f7c617a200c41c3506097f0d15fc193a1c93bfd8f141007b47cac8f95d3c AS builder-base
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .

# ── plain builder ───────────────────────────────────────────────
FROM builder-base AS builder-plain
RUN cargo build --release -p huginn-proxy

# ── ebpf builder ────────────────────────────────────────────────
FROM builder-base AS builder-ebpf
# bpf-linker uses aya-rustc-llvm-proxy which needs LLVM shared libs from
# the rustc distribution. glibc-based image required (Alpine/musl won't work).
RUN rustup toolchain install nightly --component rust-src
RUN cargo +nightly install bpf-linker --locked
RUN cargo build --release -p huginn-proxy --features ebpf-tcp

# ── runtime base ────────────────────────────────────────────────
# debian:trixie-slim — matches rust:1.94.1-slim base (Debian 13, glibc 2.38+).
FROM debian:trixie-slim@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e AS runtime-base
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --uid 10001 app

# ── plain target ────────────────────────────────────────────────
FROM runtime-base AS plain
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net (no eBPF/XDP)"
COPY --from=builder-plain /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
RUN chmod 555 /usr/local/bin/huginn-proxy \
    && rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg
USER 10001
CMD ["/usr/local/bin/huginn-proxy", "/config/config.toml"]

# ── ebpf target (default) ──────────────────────────────────────
FROM runtime-base AS ebpf
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net"
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder-ebpf /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
# cap_bpf: open pinned BPF maps for reading (TCP SYN fingerprinting).
# The proxy never loads XDP — cap_net_admin and cap_perfmon are NOT needed.
# docker-compose.yml must declare cap_add: [CAP_BPF] for the bounding set.
RUN setcap cap_bpf+eip /usr/local/bin/huginn-proxy \
    && chmod 555 /usr/local/bin/huginn-proxy \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt \
    && rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg
USER 10001
CMD ["/usr/local/bin/huginn-proxy", "/config/config.toml"]
