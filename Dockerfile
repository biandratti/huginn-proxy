FROM rust:1.85-slim AS builder
# bpf-linker (required for BPF ELF linking) uses aya-rustc-llvm-proxy which
# needs LLVM shared libs from the rustc distribution. Those libs are only
# available in glibc-based rustup toolchains, so Alpine/musl cannot be used
# as the builder image.
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
# Install nightly + rust-src to compile huginn-proxy-ebpf-xdp (bpfel-unknown-none).
# bpfel-unknown-none is Tier 3: built from source via build-std, no rustup target needed.
RUN rustup toolchain install nightly --component rust-src
# bpf-linker links the BPF ELF produced by aya-ebpf.
# --locked pins deps to bpf-linker's published Cargo.lock.
# Compiled with +nightly because bpf-linker's deps require rustc > 1.85 (stable base).
RUN cargo +nightly install bpf-linker --locked
WORKDIR /app
COPY . .
RUN cargo build --release -p huginn-proxy --features ebpf-tcp

FROM debian:bookworm-slim
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net"
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    ca-certificates wget libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
RUN adduser --disabled-password --gecos '' app
WORKDIR /app
COPY --from=builder /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
# Grant the minimum Linux capabilities needed for eBPF/XDP fingerprinting:
#   cap_bpf       – create BPF maps and load BPF programs
#   cap_net_admin – attach XDP programs to network interfaces
#   cap_perfmon   – allow pointer arithmetic in BPF verifier (required for XDP packet parsing)
# The container runs as the unprivileged 'app' user; docker-compose.yml must
# declare the same caps via cap_add so they are included in the bounding set.
RUN setcap cap_bpf,cap_net_admin,cap_perfmon+eip /usr/local/bin/huginn-proxy
# Note: Certificate files mounted as volumes need to be readable by user 'app'
# The volumes are mounted as 'ro' (read-only), so ensure proper permissions on host
USER app
CMD ["/usr/local/bin/huginn-proxy", "/config/compose.toml"]
