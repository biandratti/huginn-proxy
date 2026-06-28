use std::collections::HashMap;
use std::sync::Arc;

use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::tls::cert_resolver::DynamicCertResolver;

/// SNI-routing certificate resolver that fronts the static [`DynamicCertResolver`] with
/// per-host ACME resolvers.
///
/// Each ACME-managed host owns one resolver (produced by `huginn-acme`, one `AcmeState`
/// per domain). A handshake whose SNI matches an ACME host is delegated to that resolver,
/// which internally serves either the TLS-ALPN-01 challenge cert or the production cert.
/// Every other connection (static hosts, wildcards, no-SNI/IP clients) falls through to the
/// existing `DynamicCertResolver`, so file-based certs and hot-reload behave exactly as before.
///
/// ## Why route by SNI instead of probing each resolver
///
/// `ClientHello` is neither `Clone` nor `Copy` and `ResolvesServerCert::resolve` consumes it
/// by value, so only **one** inner `resolve()` can run per handshake. The owner of each SNI is
/// unambiguous (each host resolves to exactly one `CertSource`), so a single
/// `host → resolver` table decides the route up front using the borrowing `server_name()`
/// accessor, then moves the `ClientHello` into exactly one inner `resolve()`.
pub struct CompositeResolver {
    /// The file-based resolver, shared (via its `ArcSwap`) with the hot-reload path so static
    /// cert updates remain visible here without rebuilding the composite.
    static_certs: Arc<DynamicCertResolver>,
    /// Exact host → ACME resolver. Keys are lowercased for case-insensitive SNI matching,
    /// matching [`DynamicCertResolver`]'s convention (rustls already lowercases the SNI).
    acme_by_host: HashMap<String, Arc<dyn ResolvesServerCert>>,
}

impl std::fmt::Debug for CompositeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeResolver")
            .field("static_certs", &self.static_certs)
            .field("acme_hosts", &self.acme_by_host.len())
            .finish()
    }
}

impl CompositeResolver {
    /// Build a composite from the shared static resolver and the `(host, resolver)` pairs
    /// produced by `huginn-acme`. Hosts are lowercased so SNI lookup is case-insensitive.
    pub fn new(
        static_certs: Arc<DynamicCertResolver>,
        acme_resolvers: Vec<(String, Arc<dyn ResolvesServerCert>)>,
    ) -> Self {
        let acme_by_host = acme_resolvers
            .into_iter()
            .map(|(host, resolver)| (host.to_ascii_lowercase(), resolver))
            .collect();
        Self { static_certs, acme_by_host }
    }

    /// Pick the ACME resolver owning `sni`, if any. Borrows (does not consume) so the caller
    /// can still move the `ClientHello` into the chosen resolver afterwards.
    fn acme_for(&self, sni: Option<&str>) -> Option<&Arc<dyn ResolvesServerCert>> {
        sni.and_then(|s| self.acme_by_host.get(s))
    }

    /// `true` when at least one cert is serviceable: any static cert (exact/wildcard/default)
    /// **or** any ACME host. Composite-aware so an ACME-only deploy (no file certs) does not
    /// trip the spurious "no serviceable cert" warning in `server.rs`/`reload.rs`.
    pub fn has_serviceable_cert(&self) -> bool {
        self.static_certs.has_serviceable_cert() || !self.acme_by_host.is_empty()
    }

    /// Test-only: does `sni` route to an ACME resolver (vs. falling through to static)?
    #[doc(hidden)]
    pub fn routes_to_acme(&self, sni: Option<&str>) -> bool {
        self.acme_for(sni).is_some()
    }
}

impl ResolvesServerCert for CompositeResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Decide the route with the borrowing accessor before moving `client_hello`.
        if let Some(acme) = self.acme_for(client_hello.server_name()) {
            // The ACME resolver handles both the challenge (acme-tls/1) and production cert.
            return acme.resolve(client_hello);
        }
        // Static host, wildcard, or no SNI: the file-based resolver (unchanged behavior).
        self.static_certs.resolve(client_hello)
    }
}
