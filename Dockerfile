# rust:1.85-slim (amd64)
FROM rust:1.85-slim@sha256:3490aa77d179a59d67e94239cca96dd84030b564470859200f535b942bdffedf AS builder
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

# debian:bookworm-slim (bookworm-20260202-slim, amd64)
# Distroless is not viable here: `setcap` sets file capabilities as xattrs on the binary,
# and Docker COPY --from strips xattrs, so setcap must run inside the final image.
# Distroless images do not ship libcap2-bin/setcap, making them incompatible with this approach.
FROM debian:bookworm-slim@sha256:74a21da88cf4b2e8fde34558376153c5cd80b00ca81da2e659387e76524edc73
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net"
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
# UID 10001: avoids overlap with system UIDs (0-999) and common app UIDs (1000).
RUN adduser --disabled-password --gecos '' --uid 10001 app
WORKDIR /app
COPY --from=builder /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
# Grant the minimum Linux capabilities needed for eBPF/XDP fingerprinting:
#   cap_bpf       - create BPF maps and load BPF programs
#   cap_net_admin - attach XDP programs to network interfaces
#   cap_perfmon   - allow pointer arithmetic in BPF verifier (required for XDP packet parsing)
# The container runs as the unprivileged 'app' user; docker-compose.yml must
# declare the same caps via cap_add so they are included in the bounding set.
# chmod 555: binary is root-owned and read+execute only - the app user cannot overwrite it.
# libcap2-bin is only needed to run setcap; purge it immediately after.
# apt-get/dpkg binaries are removed to prevent package installation from a compromised container.
RUN setcap cap_bpf,cap_net_admin,cap_perfmon+eip /usr/local/bin/huginn-proxy \
    && chmod 555 /usr/local/bin/huginn-proxy \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt \
    && rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg
# Note: Certificate files mounted as volumes need to be readable by user 'app'
# The volumes are mounted as 'ro' (read-only), so ensure proper permissions on host.
# Recommended runtime flags: --security-opt no-new-privileges:true --read-only
USER 10001
CMD ["/usr/local/bin/huginn-proxy", "/config/compose.toml"]
