FROM rust:1.83-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
WORKDIR /app
COPY . .
RUN cargo build --release -p huginn-proxy

FROM alpine:3.23.2
RUN apk add --no-cache ca-certificates wget
RUN adduser -D app
WORKDIR /app
COPY --from=builder /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
# Note: Certificate files mounted as volumes need to be readable by user 'app'
# The volumes are mounted as 'ro' (read-only), so ensure proper permissions on host
USER app
CMD ["/usr/local/bin/huginn-proxy", "/config/compose.toml"]

