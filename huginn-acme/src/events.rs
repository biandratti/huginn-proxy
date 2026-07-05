//! Decoupled ACME event types for observability (huginn-specific; not in rpxy-acme).
//!
//! Kept independent of any metrics crate: the binary wires a callback that translates
//! [`AcmeEvent`] into `Metrics` calls, same boundary discipline as `SynProbe`.

use std::sync::Arc;

use rustls_acme::EventOk;

/// Callback invoked for every ACME state-machine event, receiving `(domain, event)`.
pub type OnAcmeEvent = Arc<dyn Fn(&str, AcmeEvent) + Send + Sync>;

/// A normalized, metrics-ready view of one ACME state-machine event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeEvent {
    /// A brand-new certificate was issued or renewed and hot-swapped into the resolver.
    /// This is the primary signal for the renewal-success counter.
    DeployedNewCert,
    /// A previously-cached certificate was loaded from disk at startup.
    /// Does not count as a renewal; it is a successful startup signal.
    DeployedCachedCert,
    /// The certificate or ACME account was persisted to the on-disk cache.
    CacheStored,
    /// Any error in the issuance / renewal / cache cycle.
    Error,
}

/// Map a `rustls-acme` [`EventOk`] to our decoupled [`AcmeEvent`].
pub fn acme_event_from_ok(ok: &EventOk) -> AcmeEvent {
    match ok {
        EventOk::DeployedNewCert => AcmeEvent::DeployedNewCert,
        EventOk::DeployedCachedCert => AcmeEvent::DeployedCachedCert,
        EventOk::CertCacheStore | EventOk::AccountCacheStore => AcmeEvent::CacheStored,
    }
}
