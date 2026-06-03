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
}

/// SNI-based certificate resolver populated from `DynamicConfig.domains`.
///
/// Cert maps are swapped atomically via `ArcSwap` so `resolve()` (called on
/// every TLS handshake) never blocks. `update()` builds the new maps async,
/// then swaps them in with a single pointer store.
pub struct DynamicCertResolver {
    inner: ArcSwap<CertMap>,
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map = self.inner.load();
        f.debug_struct("DynamicCertResolver")
            .field("exact_domains", &map.exact.len())
            .field("wildcard_domains", &map.wildcard.len())
            .finish()
    }
}

impl Default for DynamicCertResolver {
    fn default() -> Self {
        Self { inner: ArcSwap::new(Arc::new(CertMap::default())) }
    }
}

impl DynamicCertResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reload cert maps from `domains`. Domains without `cert_path`/`key_path` are skipped.
    ///
    /// On error the function returns early and the old cert map stays in place.
    /// Metrics are emitted per-domain.
    pub async fn update(&self, domains: &[Domain], metrics: &Metrics) -> Result<()> {
        let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
        let mut wildcard: HashMap<String, Arc<CertifiedKey>> = HashMap::new();

        for domain in domains {
            let (cert_path, key_path) = match (&domain.cert_path, &domain.key_path) {
                (Some(c), Some(k)) => (c.as_str(), k.as_str()),
                _ => continue,
            };

            let certs_keys =
                match read_certs_and_keys(Path::new(cert_path), Path::new(key_path)).await {
                    Ok(ck) => ck,
                    Err(e) => {
                        metrics.record_tls_cert_reload_error(&domain.host);
                        return Err(e);
                    }
                };

            let signing_key =
                tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&certs_keys.key)
                    .map_err(|e| {
                        metrics.record_tls_cert_reload_error(&domain.host);
                        ProxyError::Tls(format!(
                            "Failed to build signing key for '{}': {e}",
                            domain.host
                        ))
                    })?;

            let cert_hash = cert_chain_hash(&certs_keys.certs);
            let certified_key = Arc::new(CertifiedKey::new(certs_keys.certs, signing_key));

            if let Some(base) = domain.host.strip_prefix("*.") {
                wildcard.insert(base.to_string(), certified_key);
            } else {
                exact.insert(domain.host.clone(), certified_key);
            }

            metrics.record_tls_cert_reload_success(&domain.host, cert_hash);
        }

        self.inner.store(Arc::new(CertMap { exact, wildcard }));
        Ok(())
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let map = self.inner.load();

        if let Some(key) = map.exact.get(sni) {
            return Some(Arc::clone(key));
        }

        // Wildcard: strip the leftmost label and look up the base domain.
        // `*.example.com` matches `sub.example.com` but NOT `a.b.example.com`.
        let dot = sni.find('.')?;
        let base = &sni[dot.saturating_add(1)..];
        map.wildcard.get(base).map(Arc::clone)
    }
}
