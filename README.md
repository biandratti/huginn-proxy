# Huginn Proxy

Reverse proxy focused on fingerprinting (TCP SYN, HTTP, TLS) with high-performance L4 forwarding and optional TLS termination.

## Goals
- L4-first design: fast TCP forwarding with minimal overhead.
- Optional TLS termination (rustls) to inspect and route HTTP.
- Fingerprinting-first: inject fingerprints to backends via headers (`X-Huginn-TCP-FP`, `X-Huginn-HTTP-FP`, `X-Huginn-TLS-F`).
- No WebSocket/upgrade features or heavy L7 extras; simple HTTP/1.1 routing via peeking or after TLS termination.

## Fingerprints sent to backend
- `X-Huginn-TCP-FP`: hash + key TCP SYN options (MSS, WS, SACK, TS, order).
- `X-Huginn-HTTP-FP`: HTTP/1.1 request line + header order (cleartext or after TLS termination).
- `X-Huginn-TLS-F`: ClientHello fingerprint (ciphers, ALPN, extensions/order) when TLS is terminated.

