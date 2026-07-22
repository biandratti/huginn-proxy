#![forbid(unsafe_code)]

//! TLS certificate material and SNI-based resolution for huginn-proxy.
//!
//! This crate owns everything about *which certificate to serve* and *how cert
//! material is loaded from disk*, kept separate from the proxy's TLS stack
//! (acceptor, cipher suites, mTLS, session resumption) which lives in
//! `huginn-proxy-lib::tls`.
//!
//! Module layout mirrors the file names of [`rpxy-certs`](https://github.com/junkurihara/rust-rpxy)
//! for side-by-side navigation, but the model is huginn's own: a single
//! `ServerConfig` fed by one [`server_crypto::DynamicCertResolver`] (exact +
//! wildcard + catch-all + `sni_strict`), reloaded atomically from the proxy's
//! config hot-reload path — not the per-SNI `HashMap<SNI, ServerConfig>` +
//! polling model of rpxy.
//!
//! | File | Responsibility |
//! |------|----------------|
//! | `error` | [`error::CertError`] |
//! | `certs` | Cert/key material read from disk + chain hashing |
//! | `crypto_source` | Cert source description (file paths) + PEM loading |
//! | `server_crypto` | `DynamicCertResolver`, SNI cert map, atomic reload |

pub mod certs;
pub mod crypto_source;
pub mod error;
pub mod server_crypto;

pub use certs::{cert_chain_hash, ServerCertsKeys};
pub use crypto_source::{read_certs_and_keys, CertEntry};
pub use error::CertError;
pub use server_crypto::{CertReloadReport, DynamicCertResolver};
