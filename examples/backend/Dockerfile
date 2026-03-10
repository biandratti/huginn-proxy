FROM rust:1.83-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
WORKDIR /app
# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
# Copy only the backend package (what we actually need to build)
COPY examples/backend ./examples/backend
# Copy Cargo.toml of other workspace members (required by Cargo workspace resolution)
COPY huginn-proxy/Cargo.toml ./huginn-proxy/
COPY huginn-proxy-lib/Cargo.toml ./huginn-proxy-lib/
COPY huginn-ebpf/Cargo.toml ./huginn-ebpf/
COPY huginn-ebpf-common/Cargo.toml ./huginn-ebpf-common/
COPY huginn-ebpf-agent/Cargo.toml ./huginn-ebpf-agent/
COPY examples/bpf_test/Cargo.toml ./examples/bpf_test/
COPY tests-e2e/Cargo.toml ./tests-e2e/
COPY tests-browsers/Cargo.toml ./tests-browsers/
COPY huginn-ebpf-common/src ./huginn-ebpf-common/src/
# Create minimal source files for other workspace members (Cargo requires valid packages)
# These are not built, but Cargo needs them to resolve the workspace
RUN mkdir -p huginn-proxy/src huginn-proxy-lib/src huginn-ebpf/src huginn-ebpf-agent/src examples/bpf_test/src tests-e2e/src tests-browsers/src && \
    echo 'fn main() {}' > huginn-proxy/src/main.rs && \
    echo '' > huginn-proxy-lib/src/lib.rs && \
    echo '' > huginn-ebpf/src/lib.rs && \
    echo 'fn main() {}' > huginn-ebpf-agent/src/main.rs && \
    echo 'fn main() {}' > examples/bpf_test/src/main.rs && \
    echo '' > tests-e2e/src/lib.rs && \
    echo '' > tests-browsers/src/lib.rs
RUN cargo build --release --package backend

FROM alpine:3.23.2
RUN adduser -D app
WORKDIR /app
COPY --from=builder /app/target/release/backend /usr/local/bin/backend
USER app
EXPOSE 9000
CMD ["/usr/local/bin/backend"]
