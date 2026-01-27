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
COPY tests-e2e/Cargo.toml ./tests-e2e/
COPY tests-browsers/Cargo.toml ./tests-browsers/
# Create minimal source files for other workspace members (Cargo requires valid packages)
# These are not built, but Cargo needs them to resolve the workspace
RUN mkdir -p huginn-proxy/src huginn-proxy-lib/src tests-e2e/src tests-browsers/src && \
    echo 'fn main() {}' > huginn-proxy/src/main.rs && \
    echo '' > huginn-proxy-lib/src/lib.rs && \
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

