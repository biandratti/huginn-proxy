# Multi-stage Dockerfile for huginn-proxy.
# Targets:
#   plain  - no eBPF, stable toolchain, no Linux capabilities needed.
#   ebpf   - TCP SYN fingerprinting via pinned BPF maps, needs CAP_BPF at runtime.
#
# Both targets are built with the `acme` cargo feature, so the published images include
# built-in ACME (Let's Encrypt) TLS. ACME stays inert unless an `[acme]` block is configured.
#
# Build:
#   docker build --target plain -f docker/proxy.Dockerfile .
#   docker build --target ebpf  -f docker/proxy.Dockerfile .    (or just: docker build -f ...)

# ── builder base ────────────────────────────────────────────────
FROM rust:1.97.0-slim@sha256:14c4fe50ea427dc42381a1a09a9a839c1d2346a2e508cd491bf02c659dbc0ed7 AS builder-base
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .

# ── plain builder ───────────────────────────────────────────────
FROM builder-base AS builder-plain
# CARGO_FEATURES lets callers opt in/out of feature sets at build time.
# Default includes `acme` so published images are always ACME-capable.
ARG CARGO_FEATURES=acme
RUN cargo build --release -p huginn-proxy --features "${CARGO_FEATURES}"

# ── ebpf builder ────────────────────────────────────────────────
FROM builder-base AS builder-ebpf
# bpf-linker uses aya-rustc-llvm-proxy which needs LLVM shared libs from
# the rustc distribution. glibc-based image required (Alpine/musl won't work).
ARG CARGO_FEATURES=ebpf-tcp,acme
RUN rustup toolchain install nightly --component rust-src
RUN cargo +nightly install bpf-linker --locked
RUN cargo build --release -p huginn-proxy --features "${CARGO_FEATURES}"

# ── runtime base ────────────────────────────────────────────────
# debian:trixie-slim - matches rust:1.94.1-slim base (Debian 13, glibc 2.38+).
FROM debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2 AS runtime-base
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --uid 10001 app

# ── plain target ────────────────────────────────────────────────
FROM runtime-base AS plain
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting and built-in ACME (Let's Encrypt) TLS, no eBPF/XDP"
COPY --from=builder-plain /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
# The ACME cache must be writable by the unprivileged runtime user. Creating it here means a
# named volume mounted at this path inherits the ownership on first creation.
RUN mkdir -p /var/lib/huginn-proxy/acme \
    && chown -R 10001:10001 /var/lib/huginn-proxy \
    && chmod 555 /usr/local/bin/huginn-proxy \
    && rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg
USER 10001
CMD ["/usr/local/bin/huginn-proxy", "/config/config.toml"]

# ── ebpf target (default) ──────────────────────────────────────
FROM runtime-base AS ebpf
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting and built-in ACME (Let's Encrypt) TLS, powered by Huginn Net"
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder-ebpf /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
# cap_bpf: open pinned BPF maps for reading (TCP SYN fingerprinting).
# The proxy never loads XDP - cap_net_admin and cap_perfmon are NOT needed.
# docker-compose.yml must declare cap_add: [CAP_BPF] for the bounding set.
# The ACME cache must be writable by the unprivileged runtime user (see plain target).
RUN setcap cap_bpf+eip /usr/local/bin/huginn-proxy \
    && mkdir -p /var/lib/huginn-proxy/acme \
    && chown -R 10001:10001 /var/lib/huginn-proxy \
    && chmod 555 /usr/local/bin/huginn-proxy \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt \
    && rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg
USER 10001
CMD ["/usr/local/bin/huginn-proxy", "/config/config.toml"]
