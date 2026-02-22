FROM rust:1.85-alpine AS builder
# Base deps + clang/linux-headers required for the ebpf-tcp feature (XDP BPF object compilation)
RUN apk add --no-cache musl-dev pkgconfig openssl-dev clang linux-headers
WORKDIR /app
COPY . .
RUN cargo build --release -p huginn-proxy --features ebpf-tcp

FROM alpine:3.23.2
LABEL org.opencontainers.image.description="High-performance reverse proxy with passive fingerprinting capabilities powered by Huginn Net"
# libcap provides setcap; required when the ebpf-tcp feature is compiled in so the
# binary can create BPF maps and attach XDP programs without running as root.
RUN apk add --no-cache ca-certificates wget libcap
RUN adduser -D app
WORKDIR /app
COPY --from=builder /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
# Grant the minimum Linux capabilities needed for eBPF/XDP fingerprinting:
#   cap_bpf       – create BPF maps and load BPF programs
#   cap_net_admin – attach XDP programs to network interfaces
#   cap_perfmon   – allow pointer arithmetic in BPF verifier (required for XDP packet parsing)
# The container still runs as the unprivileged 'app' user; the host's
# docker-compose.yml must set  privileged: true  (or cap_add the same caps)
# so these ambient capabilities are honoured inside the container.
RUN setcap cap_bpf,cap_net_admin,cap_perfmon+eip /usr/local/bin/huginn-proxy
# Note: Certificate files mounted as volumes need to be readable by user 'app'
# The volumes are mounted as 'ro' (read-only), so ensure proper permissions on host
USER app
CMD ["/usr/local/bin/huginn-proxy", "/config/compose.toml"]