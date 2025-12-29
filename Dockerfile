FROM rust:1.82 as builder
WORKDIR /app
COPY . .
RUN cargo build --release -p huginn-proxy

FROM debian:stable-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/huginn-proxy /usr/local/bin/huginn-proxy
CMD ["/usr/local/bin/huginn-proxy", "/config/compose.toml"]

