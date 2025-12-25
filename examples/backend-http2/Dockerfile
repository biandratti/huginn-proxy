FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:3.20
RUN adduser -D app
WORKDIR /app
COPY --from=builder /app/target/release/backend-http2 /usr/local/bin/backend-http2
USER app
EXPOSE 9000
CMD ["/usr/local/bin/backend-http2"]

