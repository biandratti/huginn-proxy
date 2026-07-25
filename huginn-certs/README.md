# huginn-certs

TLS certificate material and per-SNI `ServerConfig` construction for huginn-proxy.

This crate owns which certificate to serve, how cert material is loaded from disk, and how
each domain's rustls `ServerConfig` is built (cipher suites, ALPN, per-domain mTLS verifier,
session tickets). It stays config- and telemetry-agnostic: the proxy maps its own config
onto `TlsBuildOptions` and swaps the result atomically on reload.

## Alignment with rpxy-certs

The crate is modeled after `rpxy-certs` (the cert crate in rust-rpxy). The file layout
mirrors it on purpose so both are easy to read side by side:

- `error.rs`: typed `CertError`.
- `certs.rs`: server cert/key material, client-CA anchors, chain hashing.
- `crypto_source.rs`: the `CryptoSource` trait and the file-based source (PEM from disk).
- `cipher_suites.rs`: cipher suite name mapping.
- `kx_groups.rs`: key-exchange group (curve) name mapping.
- `server_crypto.rs`: builds one `ServerConfig` per domain plus the shared ticketer.

The core model matches rpxy: one rustls `ServerConfig` per domain, selected by SNI at
handshake time. This is required because rustls binds the client-cert verifier to the
`ServerConfig`, so per-domain mTLS needs a config per domain.

## What we kept and what we changed

Kept from rpxy:

- One `ServerConfig` per domain, selected by SNI.
- Per-domain mTLS: `client_ca_path` lives next to the cert material.
- Stateless session tickets from a single process-wide ticketer; mTLS domains never resume.
- Client-CA trust anchors deduplicated by Subject Key Identifier (via `x509-parser`).

Changed on purpose:

- Resolution is exact, then wildcard, then catch-all, plus `sni_strict` (Traefik style).
  rpxy is exact-match only, with no catch-all.
- Hot reload is driven by the proxy config path (SIGHUP or file watch), not an internal
  poller. rpxy uses its own `hot_reload` crate.
- TLS versions and `curve_preferences` are enforced from config; rpxy uses provider defaults.
- Uses `arc-swap` for the atomic map swap.

Not included:

- No aggregated QUIC/HTTP3 config. rpxy builds one for h3; huginn has no h3 yet. If HTTP/3
  is added, build it for non-mTLS domains only, like rpxy.

## Keeping future changes in line

When extending this crate, put new logic in the file that matches its rpxy counterpart, keep
the crate free of proxy config and telemetry types, and keep the per-SNI `ServerConfig` model.
