# huginn-acme

> **Experimental.** This is the most operationally constrained integration in huginn-proxy.
> The core functionality (issuance, renewal, hot-swap) is production-ready for a
> **single-replica** deployment. Horizontal scaling requires delegating to an external issuer
> (cert-manager) rather than this in-process integration.

Automatic TLS certificate issuance and renewal for [`huginn-proxy`], isolated in its own crate.

Built directly on [`rustls-acme`]. Its structure and behavior are modeled after [`rpxy-acme`]
(by junkurihara) as a **reference** - not a dependency.

## What it does

- Issues and renews certificates for **exact domains** via `rustls-acme`. Kept in a dedicated
  crate so the `smol`/`async-io` reactor that `rustls-acme` pulls in stays **out of the core
  library** (`huginn-proxy-lib`).
- Certificates are served through a `CompositeResolver` (in the library) that **routes by SNI**
  between static (file) certs and ACME certs. Challenges are handled over **TLS-ALPN-01 on port
  443** - no port 80 / HTTP-01 needed.
- Directory TLS trusts the **OS trust store** by default (via `rustls-platform-verifier`);
  `directory_ca_path` overrides it to trust a private/test CA (e.g. Pebble).
- Uses `aws-lc-rs` with an **explicit crypto provider** (never `CryptoProvider::install_default`),
  so no global crypto state is installed.
- Secure on-disk cache: files `0600` inside `0700` directories, with **write access verified at
  startup** (fail-fast) before any issuance begins.
- Observability via an `OnAcmeEvent` callback emitting a decoupled `AcmeEvent` (same boundary
  discipline as the eBPF `SynProbe`); the binary translates it into metrics. Readiness (`/ready`)
  is gated on the first deployed certificate.

The crate takes primitives in and hands back `(host, resolver)` pairs plus background tasks; it
never depends on `huginn-proxy-lib`.

## Scope (supported)

- Exact hostnames (e.g. `api.example.com`).
- Multiple ACME account contacts.
- Let's Encrypt production/staging, or a custom `directory_url` (private CA / Pebble).
- N domains - one `AcmeState` and one certificate per domain.
- Coexistence with static (`cert = { type = "file" }`) certs, including wildcards issued
  externally (cert-manager) and mounted as files.

## Limitations (out of scope)

- **No wildcards** (`*.example.com`) - ACME here is TLS-ALPN-01 only. Use DNS-01 via cert-manager
  (or Caddy/lego) and consume the result as `cert = { type = "file" }`.
- **No catch-all / host-less certificate** - a domain must declare an exact `host`.
- **mTLS `client_auth` (required) is rejected** - incompatible with TLS-ALPN-01 validation: a
  single `ServerConfig` serves both challenge and production, and the CA's validation handshake
  presents no client certificate. Terminate mTLS on a separate listener/domain without ACME.
- **Single-replica cache** - `DirCache` lives on the local filesystem; N replicas would each
  issue their own certificates. For multi-replica / HA, delegate to cert-manager (or a shared
  cache backend, not yet implemented).
- **No EAB** (External Account Binding) - `rustls-acme` does not expose it, so CAs that require it
  (ZeroSSL, Google Public CA, Sectigo) must be used via a file cert.
- **No per-domain ACME config** (single `[acme]` account/CA), **no cert tuning** (key type,
  renewal window, multiple SANs), and **no OCSP stapling**.
- The **ACME domain set is fixed at startup** - adding or removing an ACME domain requires a
  restart. File certs and routes remain hot-reloadable.

[`huginn-proxy`]: https://github.com/biandratti/huginn-proxy

[`rustls-acme`]: https://docs.rs/rustls-acme

[`rpxy-acme`]: https://github.com/junkurihara/rust-rpxy
