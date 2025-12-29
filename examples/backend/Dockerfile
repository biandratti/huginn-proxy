FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY examples/backend ./examples/backend
# Copy workspace members Cargo.toml (needed for workspace structure)
COPY huginn-proxy/Cargo.toml ./huginn-proxy/
COPY huginn-proxy-lib/Cargo.toml ./huginn-proxy-lib/
# Create minimal source files
RUN mkdir -p huginn-proxy/src huginn-proxy-lib/src && \
    echo 'fn main() {}' > huginn-proxy/src/main.rs && \
    echo '' > huginn-proxy-lib/src/lib.rs
RUN cargo build --release --package backend

FROM alpine:3.23.2
RUN adduser -D app
WORKDIR /app
COPY --from=builder /app/target/release/backend /usr/local/bin/backend
USER app
EXPOSE 9000
CMD ["/usr/local/bin/backend"]

