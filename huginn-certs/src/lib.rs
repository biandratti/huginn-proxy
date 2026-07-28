#![forbid(unsafe_code)]

//! TLS certificate material and per-SNI `ServerConfig` construction for huginn-proxy.
//!
//! This crate owns *which certificate to serve*, *how cert material is loaded from
//! disk*, and *how each domain's rustls `ServerConfig` is built* (cipher suites,
//! ALPN, per-domain mTLS verifier, session tickets). The proxy's `huginn-proxy-lib::tls`
//! only projects its static config onto [`TlsBuildOptions`], drives the accept path,
//! and swaps the resulting map atomically.
//!
//! Module layout mirrors the file names of [`rpxy-certs`](https://github.com/junkurihara/rust-rpxy)
//! for side-by-side navigation. Like rpxy, the crate builds **one rustls
//! `ServerConfig` per domain** ([`server_crypto::build_server_crypto`]), selected at
//! handshake time by SNI. Unlike rpxy's exact-match-only `HashMap<SNI, config>`,
//! the [`ServerCryptoMap`] keeps huginn's resolution model (`exact → wildcard →
//! catch-all` with `sni_strict`) and is swapped atomically by the proxy's config
//! hot-reload path.
//!
//! | File | Responsibility |
//! |------|----------------|
//! | `error` | [`error::CertError`] |
//! | `certs` | Cert/key material read from disk + chain hashing |
//! | `crypto_source` | Cert source description (file paths) + PEM loading |
//! | `cipher_suites` | Cipher-suite name ⇄ rustls type mapping |
//! | `kx_groups` | Key-exchange group (curve) name ⇄ rustls type mapping |
//! | `server_crypto` | Per-SNI `ServerConfig` map (`build_server_crypto`) + shared ticketer |

pub mod certs;
pub mod cipher_suites;
pub mod crypto_source;
pub mod error;
pub mod kx_groups;
pub mod server_crypto;

pub use certs::{cert_chain_hash, ServerCertsKeys};
pub use cipher_suites::{CipherSuiteName, UnknownCipherSuite};
pub use crypto_source::{read_certs_and_keys, CertEntry, CryptoFileSource, CryptoSource};
pub use error::CertError;
pub use kx_groups::{KxGroupName, UnknownKxGroup};
pub use server_crypto::{
    build_server_crypto, CertReloadReport, ServerCryptoForSni, ServerCryptoMap, TlsBuildOptions,
};
