# Multi-stage Dockerfile for huginn-proxy.
# Targets:
#   plain  — no eBPF, stable toolchain, no Linux capabilities needed.
#   ebpf   — TCP SYN fingerprinting via pinned BPF maps, needs CAP_BPF at runtime.
#
# Build:
#   docker build --target plain -f docker/proxy.Dockerfile .
#   docker build --target ebpf  -f docker/proxy.Dockerfile .    (or just: docker build -f ...)

# ── builder base ────────────────────────────────────────────────
FROM rust:1.98.1-slim@sha256:ce84a5edd80c5f91e05c5533b1e53eb1da54028f33734dc06aa6b49fa190462d AS builder-base
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN rustc --edition=2021 -O docker/healthcheck.rs -o /healthcheck

# ── plain builder ───────────────────────────────────────────────
FROM builder-base AS builder-plain
RUN cargo build --release -p huginn-proxy

# ── ebpf builder ────────────────────────────────────────────────
FROM builder-base AS builder-ebpf
# bpf-linker 0.11+ needs a matching LLVM when built from source; install the prebuilt binary instead.
RUN rustup toolchain install nightly --component rust-src
ARG TARGETARCH
ADD https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz /tmp/cargo-binstall-amd64.tgz
ADD https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-aarch64-unknown-linux-musl.tgz /tmp/cargo-binstall-arm64.tgz
RUN tar -xzf /tmp/cargo-binstall-${TARGETARCH}.tgz -C /usr/local/cargo/bin cargo-binstall \
    && rm /tmp/cargo-binstall-*.tgz \
    && cargo binstall bpf-linker --no-confirm
RUN cargo build --release -p huginn-proxy --features ebpf-tcp

# ── runtime base ────────────────────────────────────────────────
# Distroless contains only the glibc/libgcc runtime and CA store needed by the binaries.
FROM gcr.io/distroless/cc-debian13:latest@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750 AS runtime-base
COPY --from=builder-base /healthcheck /usr/local/bin/healthcheck

# ── plain target ────────────────────────────────────────────────
FROM runtime-base AS plain
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net (no eBPF/XDP)"
COPY --from=builder-plain /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
USER 10001
CMD ["/usr/local/bin/huginn-proxy", "/config/config.toml"]

# ── ebpf target (default) ──────────────────────────────────────
FROM runtime-base AS ebpf
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net"
COPY --from=builder-ebpf /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
# The runtime must grant CAP_BPF (Compose cap_add / Kubernetes securityContext).
# The proxy only reads pinned maps; CAP_NET_ADMIN and CAP_PERFMON are not needed.
USER 10001
CMD ["/usr/local/bin/huginn-proxy", "/config/config.toml"]
