//! ACME (Let's Encrypt) adapter for huginn-proxy, isolated in its own crate.
//!
//! Structure and behavior are aligned with [`rpxy-acme`] (by junkurihara), the reference
//! implementation this adapter is modeled after: same module layout ([`constants`],
//! [`dir_cache`], [`error`], [`manager`]) with `lib.rs` kept as pure wiring.
//!
//! [`rpxy-acme`]: https://github.com/junkurihara/rust-rpxy

#![forbid(unsafe_code)]

pub mod constants;
pub mod dir_cache;
pub mod error;
pub mod manager;

pub use constants::{LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING};
pub use dir_cache::DirCache;
pub use error::AcmeError;
pub use manager::{acme_event_from_ok, start_acme, AcmeEvent, AcmeHandles, OnAcmeEvent};
