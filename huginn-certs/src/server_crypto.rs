//! SNI-based certificate resolution and atomic hot-reload.
//!
//! [`DynamicCertResolver`] implements rustls' [`ResolvesServerCert`] over a cert
//! map swapped atomically via `ArcSwap`, so `resolve()` (called on every TLS
//! handshake) never blocks. [`DynamicCertResolver::update`] rebuilds the map from
//! a list of [`CertEntry`] and swaps it in with a single pointer store.
//!
//! Resolution order is exact → wildcard → default (catch-all), with `sni_strict`
//! parity to Traefik's `sniStrict`. This is huginn's model, not rpxy's per-SNI
//! `HashMap<SNI, ServerConfig>`.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tracing::{info, warn};

use crate::certs::cert_chain_hash;
use crate::crypto_source::{CertEntry, CryptoSource};
use crate::error::CertError;

/// Outcome of a [`DynamicCertResolver::update`] call.
///
/// `update()` is best-effort per-domain: it always performs the atomic swap and
/// loads as many certs as it can. `loaded` holds `(label, cert_hash)` for each
/// domain whose cert went live in this call; `failed` holds the labels of domains
/// whose cert could not be loaded (those keep their previously serving cert, if
/// any). A non-empty `failed` is a *partial* reload.
///
/// The report carries labels and hashes rather than emitting metrics itself, so
/// the crate stays free of any telemetry dependency: the caller
/// (huginn-proxy-lib) records `tls_cert_reload_*` from this report *after*
/// `update` returns, i.e. after the atomic swap.
#[derive(Debug, Default, Clone)]
pub struct CertReloadReport {
    /// `(label, cert_hash)` per cert that went into service this reload.
    pub loaded: Vec<(String, u64)>,
    /// Labels of domains whose cert failed to load this reload.
    pub failed: Vec<String>,
}

impl CertReloadReport {
    /// `true` when at least one domain's cert failed to load this reload.
    pub fn is_partial(&self) -> bool {
        !self.failed.is_empty()
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
    /// In lenient mode it is served for connections with no SNI (IP clients,
    /// RFC 6066) and for SNI that matches no exact/wildcard entry, equivalent to
    /// Traefik's `defaultCertificate`. `None` (no catch-all cert), or `sni_strict`,
    /// disables this fallback so those connections are rejected (rustls sends
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

/// SNI-based certificate resolver populated from a list of [`CertEntry`].
///
/// Cert maps are swapped atomically via `ArcSwap` so `resolve()` (called on
/// every TLS handshake) never blocks. `update()` builds the new maps async,
/// then swaps them in with a single pointer store.
pub struct DynamicCertResolver {
    inner: ArcSwap<CertMap>,
    /// Strict SNI mode - full parity with Traefik's `sniStrict`. When `true`, the
    /// default-cert fallback is disabled for *both* cases: an SNI that matches no
    /// exact/wildcard cert is rejected, and a connection with **no** SNI (IP-literal
    /// clients, RFC 6066) is rejected too (`resolve` returns `None` → rustls
    /// `unrecognized_name`). When `false`, both cases fall back to the default cert.
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

    /// Reload cert maps from `entries`.
    ///
    /// Best-effort, per-domain: a domain whose cert fails to load does **not** abort the
    /// reload. The atomic swap always runs with every cert that loaded successfully, and a
    /// failing domain keeps its *previously serving* cert (carried over from the old map) so
    /// a bad file mid-rotation never takes that domain offline. The returned
    /// [`CertReloadReport`] lists which certs loaded (with their chain hash) vs. which
    /// failed; a non-empty `failed` is a partial reload.
    ///
    /// The report's `loaded` list is built as certs go into `next` and returned only after
    /// the atomic swap, so a caller that records success metrics from it never advertises a
    /// certificate that didn't actually go into service (carried-over certs are not listed
    /// as loaded; no spurious success is emitted for them).
    pub async fn update(&self, entries: &[CertEntry]) -> CertReloadReport {
        let old = self.inner.load();
        let mut next = CertMap::default();
        let mut loaded: Vec<(String, u64)> = Vec::new();
        let mut failed: Vec<String> = Vec::new();

        for entry in entries {
            let label = entry.label.as_str();
            let slot = classify(entry.host.as_deref());
            match load_certified_key(entry.source.as_ref(), label).await {
                Ok((certified_key, cert_hash)) => {
                    next.place(&slot, certified_key);
                    loaded.push((label.to_string(), cert_hash));
                }
                Err(e) => {
                    failed.push(label.to_string());
                    // Best-effort: carry the domain's previously serving cert forward so a
                    // transient bad cert does not drop TLS for a host that was working.
                    match old.get(&slot) {
                        Some(prev) => {
                            info!(host = label, error = %e, "Cert load failed; keeping previously loaded certificate");
                            next.place(&slot, prev);
                        }
                        None => {
                            info!(host = label, error = %e, "Cert load failed; domain has no previous certificate and will not serve TLS");
                        }
                    }
                }
            }
        }

        self.inner.store(Arc::new(next));

        CertReloadReport { loaded, failed }
    }

    /// Core SNI → cert resolution. Separated from [`ResolvesServerCert::resolve`]
    /// so it can be unit-tested without constructing a rustls `ClientHello`.
    fn resolve_sni(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let map = self.inner.load();

        // RFC 6066: IP-literal connections do not carry an SNI extension.
        // Strict mode (Traefik `sniStrict` parity) disables the default-cert
        // fallback, so a no-SNI client is rejected (`None` → rustls
        // `unrecognized_name`). Lenient mode serves the default cert so clients
        // connecting via IP (e.g. `https://127.0.0.1:7000`) can complete the
        // handshake and route by Host header. No default ⇒ reject either way.
        let Some(sni) = sni else {
            if self.sni_strict {
                return None;
            }
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

    /// `true` when the live cert map holds at least one certificate (exact, wildcard, or
    /// default). When `false` in HTTPS mode, every TLS handshake is rejected.
    pub fn has_serviceable_cert(&self) -> bool {
        let m = self.inner.load();
        !m.exact.is_empty() || !m.wildcard.is_empty() || m.default.is_some()
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

/// Read a cert/key pair from `source` and build a `(CertifiedKey, chain_hash)`.
///
/// `label` is used only to label the signing-key error. Errors are returned, not
/// recorded as metrics, so the caller decides how to treat the failure.
async fn load_certified_key(
    source: &dyn CryptoSource,
    label: &str,
) -> Result<(Arc<CertifiedKey>, u64), CertError> {
    let certs_keys = source.read().await?;
    let signing_key =
        tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&certs_keys.key)
            .map_err(|e| CertError::SigningKey {
                label: label.to_string(),
                message: e.to_string(),
            })?;
    let cert_hash = cert_chain_hash(&certs_keys.certs);
    let certified_key = Arc::new(CertifiedKey::new(certs_keys.certs, signing_key));

    match certified_key.keys_match() {
        Ok(()) => {}
        Err(tokio_rustls::rustls::Error::InconsistentKeys(
            tokio_rustls::rustls::InconsistentKeys::Unknown,
        )) => {
            warn!(
                host = label,
                "could not verify that the private key matches the certificate; proceeding"
            );
        }
        Err(e) => {
            return Err(CertError::KeyMismatch {
                label: label.to_string(),
                message: e.to_string(),
            });
        }
    }

    Ok((certified_key, cert_hash))
}
