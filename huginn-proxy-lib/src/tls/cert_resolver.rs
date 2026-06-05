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
    /// get the default cert, which also rejects those.
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
    /// On error the function returns early and the old cert map stays in place.
    /// Metrics are emitted per-domain.
    pub async fn update(&self, domains: &[Domain], metrics: &Metrics) -> Result<()> {
        let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
        let mut wildcard: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
        let mut default: Option<Arc<CertifiedKey>> = None;

        for domain in domains {
            // Label for metrics/logs; the catch-all domain has no host string.
            let host = domain.host.as_deref().unwrap_or("_default_");
            let (cert_path, key_path) = match (&domain.cert_path, &domain.key_path) {
                (Some(c), Some(k)) => (c.as_str(), k.as_str()),
                _ => continue,
            };

            let certs_keys =
                match read_certs_and_keys(Path::new(cert_path), Path::new(key_path)).await {
                    Ok(ck) => ck,
                    Err(e) => {
                        metrics.record_tls_cert_reload_error(host);
                        return Err(e);
                    }
                };

            let signing_key =
                tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&certs_keys.key)
                    .map_err(|e| {
                        metrics.record_tls_cert_reload_error(host);
                        ProxyError::Tls(format!("Failed to build signing key for '{host}': {e}"))
                    })?;

            let cert_hash = cert_chain_hash(&certs_keys.certs);
            let certified_key = Arc::new(CertifiedKey::new(certs_keys.certs, signing_key));

            match domain.host.as_deref() {
                Some(h) => match h.strip_prefix("*.") {
                    Some(base) => {
                        wildcard.insert(base.to_string(), certified_key);
                    }
                    None => {
                        exact.insert(h.to_string(), certified_key);
                    }
                },
                // Catch-all domain's cert is the TLS default certificate.
                None => default = Some(certified_key),
            }

            metrics.record_tls_cert_reload_success(host, cert_hash);
        }

        self.inner
            .store(Arc::new(CertMap { exact, wildcard, default }));
        Ok(())
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
