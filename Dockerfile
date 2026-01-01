FROM rust:1.83-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
WORKDIR /app
COPY . .
RUN cargo build --release -p huginn-proxy

FROM alpine:3.23.2
# Update package index and install only essential packages
# wget is needed for Docker Compose healthcheck
RUN apk update && \
    apk add --no-cache ca-certificates wget && \
    adduser -D -u 1000 app && \
    rm -rf /var/cache/apk/*

# Copy binary with proper ownership
COPY --from=builder --chown=app:app /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy

# Note: Certificate files mounted as volumes need to be readable by user 'app'
# The volumes are mounted as 'ro' (read-only), so ensure proper permissions on host
USER app

# Example: docker run image /path/to/config.toml
ENTRYPOINT ["/usr/local/bin/huginn-proxy"]
CMD ["/config/compose.toml"]

