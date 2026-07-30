# huginn-certs

Certificate material and per-SNI `ServerConfig` construction for huginn-proxy: what to load
from disk, which certificate to serve for an SNI, and how each domain's rustls config is
built (cipher suites, ALPN, client verifier, session tickets).

The crate knows nothing about the proxy's config or telemetry. The proxy projects its own
settings onto `TlsBuildOptions`, gets back a `ServerCryptoMap` plus a report, and swaps the
map atomically on reload.

## Model

One rustls `ServerConfig` per domain, picked by SNI during the handshake. This is not a
style choice: rustls binds the client-certificate verifier to the `ServerConfig`, so mTLS
can only be per-domain if the config is too. The model, and the file layout below, follow
`rpxy-certs` (the cert crate of rust-rpxy) so both stay easy to read side by side.

| File | Contents | rpxy counterpart |
|---|---|---|
| `error.rs` | Typed `CertError` | yes |
| `certs.rs` | Server cert/key material, client-CA anchors, chain hashing | yes |
| `crypto_source.rs` | `CryptoSource` trait and the PEM-from-disk source | yes |
| `server_crypto.rs` | One `ServerConfig` per domain, SNI resolution, shared ticketer | yes |
| `cipher_suites.rs` | Typed cipher suite names | no, rpxy takes provider defaults |
| `kx_groups.rs` | Typed key-exchange group names | no, same reason |

## Same as rpxy

- One `ServerConfig` per domain, selected by SNI.
- Per-domain mTLS: `client_ca_path` sits next to the cert material.
- Stateless session tickets from one process-wide ticketer, and mTLS domains never resume,
  so the client certificate is verified on every connection.
- Client-CA trust anchors deduplicated by Subject Key Identifier (`x509-parser`).

## Different from rpxy

| Topic | rpxy | huginn |
|---|---|---|
| SNI resolution | exact match only | exact, then wildcard, then catch-all, plus `sni_strict` (Traefik style) |
| Hot reload | its own poller (`hot_reload` crate) | driven by the proxy's config path (SIGHUP or file watch), swapped with `arc-swap` |
| TLS versions and curves | provider defaults | enforced from config when set |
| Key that goes with the chain | first key the provider accepts, never compared to the certificate | every key is tried and the one matching the chain wins (`keys_match`) |
| Client CA without a SKID extension | dropped | trusted, keyed by its DER instead |
| Client CA rustls cannot turn into an anchor | skipped silently | fails the domain, naming its position in the bundle and its subject |
| Domain whose mTLS material fails to load | keeps going, possibly without a verifier | parked on a reject sentinel, never served unauthenticated |

Also here and not in rpxy: a stable FNV-1a hash of the certificate chain, which the proxy
exports as a metric so a rotation is visible without reading the files.

## Not included

No aggregated QUIC/HTTP3 config: rpxy builds one for h3 and huginn has no h3 yet. If it is
added, build it for non-mTLS domains only, as rpxy does.

## Extending it

Put new logic in the file matching its rpxy counterpart, keep proxy config and telemetry
types out of the crate, and keep the per-SNI model. Behaviour that a client can observe
(above all client authentication) is worth a real handshake in `tests/`, since a flag on the
built config can keep saying the right thing after the behaviour stops matching it.
