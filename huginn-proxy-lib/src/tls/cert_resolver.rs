use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::config::Domain;
use crate::error::{ProxyError, Result};
use crate::telemetry::Metrics;
use crate::tls::cert_source::{cert_chain_hash, read_certs_and_keys};
use tracing::error;

/// Outcome of a [`DynamicCertResolver::update`] call.
///
/// `update()` is best-effort per-domain: it always performs the atomic swap and
/// loads as many certs as it can. `loaded` counts domains whose cert went live
/// in this call; `failed` counts domains whose cert could not be loaded (those
/// keep their previously serving cert, if any). `failed > 0` is a *partial* reload.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CertReloadReport {
    pub loaded: usize,
    pub failed: usize,
}

impl CertReloadReport {
    /// `true` when at least one domain's cert failed to load this reload.
    pub fn is_partial(&self) -> bool {
        self.failed > 0
    }
}

/// Which slot of [`CertMap`] a domain's cert belongs in, derived from its host.
enum CertSlot<'a> {
    Exact(&'a str),
    /// Base domain of a `*.base` wildcard host.
    Wildcard(&'a str),
    /// The catch-all (host-less) domain's cert = the TLS default certificate.
    Default,
}

fn classify(host: Option<&str>) -> CertSlot<'_> {
    match host {
        Some(h) => match h.strip_prefix("*.") {
            Some(base) => CertSlot::Wildcard(base),
            None => CertSlot::Exact(h),
        },
        None => CertSlot::Default,
    }
}

#[derive(Default)]
struct CertMap {
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// Keyed by base domain (e.g. `"example.com"` for `"*.example.com"`).
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    /// Cert from the catch-all (host-less) domain, if it declares one.
    /// Served for connections with no SNI (IP clients, RFC 6066) and for SNI
    /// that matches no exact/wildcard entry — equivalent to Traefik's
    /// `defaultCertificate`. `None` ⇒ unknown SNI is rejected (rustls sends
    /// `unrecognized_name`), equivalent to Traefik `sniStrict: true`.
    default: Option<Arc<CertifiedKey>>,
}

impl CertMap {
    /// Insert a cert into the slot dictated by its host shape.
    fn place(&mut self, slot: &CertSlot<'_>, key: Arc<CertifiedKey>) {
        match *slot {
            CertSlot::Exact(h) => {
                self.exact.insert(h.to_string(), key);
            }
            CertSlot::Wildcard(base) => {
                self.wildcard.insert(base.to_string(), key);
            }
            CertSlot::Default => self.default = Some(key),
        }
    }

    /// Look up the cert currently in the slot for `slot` (used to carry a domain's
    /// previously serving cert forward when its new cert fails to load).
    fn get(&self, slot: &CertSlot<'_>) -> Option<Arc<CertifiedKey>> {
        match *slot {
            CertSlot::Exact(h) => self.exact.get(h).map(Arc::clone),
            CertSlot::Wildcard(base) => self.wildcard.get(base).map(Arc::clone),
            CertSlot::Default => self.default.clone(),
        }
    }
}

/// SNI-based certificate resolver populated from `DynamicConfig.domains`.
///
/// Cert maps are swapped atomically via `ArcSwap` so `resolve()` (called on
/// every TLS handshake) never blocks. `update()` builds the new maps async,
/// then swaps them in with a single pointer store.
pub struct DynamicCertResolver {
    inner: ArcSwap<CertMap>,
    /// Strict SNI mode. When `true`, an SNI that matches no exact/wildcard cert is
    /// rejected (`resolve` returns `None` → rustls `unrecognized_name`) instead of
    /// falling back to the default cert. Connections with no SNI (IP clients) still
    /// get the default cert — unlike Traefik's `sniStrict`, which also rejects those.
    sni_strict: bool,
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map = self.inner.load();
        f.debug_struct("DynamicCertResolver")
            .field("exact_domains", &map.exact.len())
            .field("wildcard_domains", &map.wildcard.len())
            .field("sni_strict", &self.sni_strict)
            .finish()
    }
}

impl Default for DynamicCertResolver {
    fn default() -> Self {
        Self::new(false)
    }
}

impl DynamicCertResolver {
    pub fn new(sni_strict: bool) -> Self {
        Self { inner: ArcSwap::new(Arc::new(CertMap::default())), sni_strict }
    }

    /// Reload cert maps from `domains`. Domains without `cert_path`/`key_path` are skipped.
    ///
    /// Best-effort, per-domain: a domain whose cert fails to load does **not** abort the
    /// reload. The atomic swap always runs with every cert that loaded successfully, and a
    /// failing domain keeps its *previously serving* cert (carried over from the old map) so
    /// a bad file mid-rotation never takes that domain offline. The returned
    /// [`CertReloadReport`] reports how many certs loaded vs. failed; `failed > 0` is a
    /// partial reload (caller emits the partial signal — see `proxy/reload.rs`).
    ///
    /// A per-domain error metric fires for each failure. Success metrics are recorded only
    /// *after* the atomic swap, so the `tls_cert_hash`/timestamp gauges always reflect a
    /// certificate that actually went into service (carried-over certs keep their existing
    /// gauge value; no spurious success is emitted for them).
    pub async fn update(&self, domains: &[Domain], metrics: &Metrics) -> CertReloadReport {
        let old = self.inner.load();
        let mut next = CertMap::default();
        // Buffered until after the swap; (host, cert_hash) per successfully loaded cert.
        let mut loaded: Vec<(String, u64)> = Vec::new();
        let mut failed: usize = 0;

        for domain in domains {
            // Label for metrics/logs; the catch-all domain has no host string.
            let host = domain.label();
            let (cert_path, key_path) = match (&domain.cert_path, &domain.key_path) {
                (Some(c), Some(k)) => (c.as_str(), k.as_str()),
                _ => continue,
            };

            let slot = classify(domain.host.as_deref());
            match load_certified_key(cert_path, key_path, host).await {
                Ok((certified_key, cert_hash)) => {
                    next.place(&slot, certified_key);
                    loaded.push((host.to_string(), cert_hash));
                }
                Err(e) => {
                    metrics.record_tls_cert_reload_error(host);
                    failed = failed.saturating_add(1);
                    // Best-effort: carry the domain's previously serving cert forward so a
                    // transient bad cert does not drop TLS for a host that was working.
                    match old.get(&slot) {
                        Some(prev) => {
                            error!(host, error = %e, "Cert reload failed; keeping previously loaded certificate");
                            next.place(&slot, prev);
                        }
                        None => {
                            error!(host, error = %e, "Cert reload failed; domain has no previously loaded certificate to fall back on");
                        }
                    }
                }
            }
        }

        self.inner.store(Arc::new(next));

        // Emit success metrics only now that the new map is live, so the gauges
        // never advertise a cert that didn't actually go into service.
        for (host, cert_hash) in &loaded {
            metrics.record_tls_cert_reload_success(host, *cert_hash);
        }

        CertReloadReport { loaded: loaded.len(), failed }
    }

    /// Core SNI → cert resolution. Separated from [`ResolvesServerCert::resolve`]
    /// so it can be unit-tested without constructing a rustls `ClientHello`.
    fn resolve_sni(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let map = self.inner.load();

        // RFC 6066: IP address connections do not carry an SNI extension.
        // With no SNI, serve the default cert (catch-all domain) so clients
        // connecting via IP (e.g. `https://127.0.0.1:7000`) can complete the
        // handshake; routing then uses the Host header. No default ⇒ reject.
        // `sni_strict` does NOT reject the no-SNI case, on purpose.
        let Some(sni) = sni else {
            return map.default.clone();
        };

        if let Some(key) = map.exact.get(sni) {
            return Some(Arc::clone(key));
        }

        // Wildcard: strip the leftmost label and look up the base domain.
        // `*.example.com` matches `sub.example.com` but NOT `a.b.example.com`.
        if let Some(dot) = sni.find('.') {
            let base = &sni[dot.saturating_add(1)..];
            if let Some(key) = map.wildcard.get(base) {
                return Some(Arc::clone(key));
            }
        }

        // SNI matched nothing. Strict ⇒ reject (`None` → rustls `unrecognized_name`).
        // Otherwise serve the default cert if one exists (Traefik default behavior).
        if self.sni_strict {
            return None;
        }
        map.default.clone()
    }

    /// Test-only snapshot of the cert map: `(exact_count, wildcard_count, has_default)`.
    /// The default cert is the one from a host-less (catch-all) domain.
    #[doc(hidden)]
    pub fn cert_map_summary(&self) -> (usize, usize, bool) {
        let m = self.inner.load();
        (m.exact.len(), m.wildcard.len(), m.default.is_some())
    }

    /// Test-only: does an SNI (or no SNI = `None`) resolve to a certificate?
    #[doc(hidden)]
    pub fn resolves_for(&self, sni: Option<&str>) -> bool {
        self.resolve_sni(sni).is_some()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_sni(client_hello.server_name())
    }
}

/// Read a cert/key pair from disk and build a `(CertifiedKey, chain_hash)`.
///
/// `host` is used only to label the signing-key error. Errors are returned, not
/// recorded as metrics, so the caller decides how to treat the failure.
async fn load_certified_key(
    cert_path: &str,
    key_path: &str,
    host: &str,
) -> Result<(Arc<CertifiedKey>, u64)> {
    let certs_keys = read_certs_and_keys(Path::new(cert_path), Path::new(key_path)).await?;
    let signing_key =
        tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&certs_keys.key)
            .map_err(|e| {
                ProxyError::Tls(format!("Failed to build signing key for '{host}': {e}"))
            })?;
    let cert_hash = cert_chain_hash(&certs_keys.certs);
    let certified_key = Arc::new(CertifiedKey::new(certs_keys.certs, signing_key));
    Ok((certified_key, cert_hash))
}
