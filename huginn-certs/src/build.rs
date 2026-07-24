//! Per-SNI `ServerConfig` construction — huginn's take on rpxy's `server_crypto`.
//!
//! [`build_server_crypto`] turns a list of [`CertEntry`] into a
//! [`ServerCryptoMap`]: one rustls [`ServerConfig`] per domain, selected at
//! handshake time by SNI. Unlike rpxy's exact-match-only `HashMap<SNI, config>`,
//! the map keeps huginn's resolution model — `exact → wildcard → catch-all` with
//! `sni_strict` — in [`ServerCryptoMap::select`].
//!
//! ## Client auth is per-domain
//!
//! rustls binds the client-certificate verifier to the `ServerConfig`, not to the
//! resolved cert, so mutual TLS can only be per-domain if each domain has its own
//! config. A domain whose material carries client-CA anchors
//! ([`ServerCertsKeys::is_mutual_tls`](crate::ServerCertsKeys::is_mutual_tls))
//! gets a [`WebPkiClientVerifier`]; every other domain gets `no_client_auth`.
//!
//! ## Resumption policy (mirrors rpxy)
//!
//! Resumption is via **stateless session tickets only** (no server-side cache):
//! the ticket keys are a single process-wide `shared_ticketer` instance shared
//! across every non-mTLS config and across hot-reloads, so outstanding tickets stay
//! decryptable when the map is rebuilt. **mTLS domains never resume** (no ticketer
//! and no cache) so the client certificate is verified on every connection —
//! a resumed handshake would otherwise restore the stored client identity without
//! re-running the verifier.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use tokio_rustls::rustls::crypto::{aws_lc_rs, CryptoProvider};
use tokio_rustls::rustls::server::{
    ClientHello, NoServerSessionStorage, ProducesTickets, ResolvesServerCert, WebPkiClientVerifier,
};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tracing::info;

use crate::certs::build_certified_key;
use crate::cipher_suites::resolve_cipher_suites;
use crate::crypto_source::CertEntry;
use crate::error::CertError;

/// Outcome of a [`build_server_crypto`] call.
///
/// The build is best-effort per-domain: it always produces a [`ServerCryptoMap`]
/// and builds as many configs as it can. `loaded` holds `(label, cert_hash)` for
/// each domain whose config went live in this build; `failed` holds the labels of
/// domains whose config could not be built (those keep their previously serving
/// config, if any). A non-empty `failed` is a *partial* build.
///
/// The report carries labels and hashes rather than emitting metrics itself, so
/// the crate stays free of any telemetry dependency: the caller (huginn-proxy-lib)
/// records `tls_cert_reload_*` from this report *after* the atomic swap.
#[derive(Debug, Default, Clone)]
pub struct CertReloadReport {
    /// `(label, cert_hash)` per config that went into service this build.
    pub loaded: Vec<(String, u64)>,
    /// Labels of domains whose config failed to build this reload.
    pub failed: Vec<String>,
}

impl CertReloadReport {
    /// `true` when at least one domain's config failed to build this reload.
    pub fn is_partial(&self) -> bool {
        !self.failed.is_empty()
    }
}

/// Process-wide stateless session ticketer, shared by every non-mTLS `ServerConfig`
/// and across certificate hot-reloads.
///
/// A single instance is required: `Ticketer::new()` generates fresh keys on every
/// call, so per-build or per-reload instances would make outstanding tickets
/// mutually undecryptable and resumption would not survive a reload.
static SHARED_TICKETER: OnceLock<Arc<dyn ProducesTickets>> = OnceLock::new();

/// Get (or lazily create) the process-wide stateless ticketer.
///
/// A racing builder only creates a transient extra ticketer that is dropped
/// unused; `get_or_init` picks a single winner.
fn shared_ticketer() -> Result<Arc<dyn ProducesTickets>, CertError> {
    if let Some(ticketer) = SHARED_TICKETER.get() {
        return Ok(Arc::clone(ticketer));
    }
    let ticketer = aws_lc_rs::Ticketer::new().map_err(|e| CertError::Ticketer(e.to_string()))?;
    Ok(Arc::clone(SHARED_TICKETER.get_or_init(|| ticketer)))
}

/// Listener-global TLS options applied to every per-SNI `ServerConfig`.
///
/// Deliberately config-agnostic (plain `std`/rustls-free of `huginn-proxy-lib`
/// types) so the crate does not depend on the proxy's config model. Only carries
/// what is actually applied at build time: TLS versions and key-exchange curves
/// are left at the provider's safe defaults (which include the post-quantum hybrid
/// group), matching rpxy.
#[derive(Debug, Clone, Default)]
pub struct TlsBuildOptions {
    /// ALPN protocols to advertise (e.g. `["h2", "http/1.1"]`). Empty = none.
    pub alpn: Vec<String>,
    /// Cipher-suite names overriding the provider defaults. Empty = provider defaults.
    pub cipher_suites: Vec<String>,
    /// When `true`, non-mTLS configs issue stateless session tickets (see module docs).
    pub resumption_enabled: bool,
    /// Strict SNI: reject unmatched / no-SNI connections instead of serving the catch-all.
    pub sni_strict: bool,
}

/// Resolves every handshake to one fixed certificate. Config selection already
/// happened by SNI, so each per-domain `ServerConfig` only ever serves its own cert.
#[derive(Debug)]
struct SingleCertResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Resolves no certificate, so rustls aborts the handshake with `unrecognized_name`.
/// Backs [`ServerCryptoMap::reject_config`] for the strict / no-match case.
#[derive(Debug)]
struct RejectResolver;

impl ResolvesServerCert for RejectResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

/// Which slot of [`ServerCryptoMap`] a domain's config belongs in, derived from its host.
enum Slot<'a> {
    Exact(&'a str),
    /// Base domain of a `*.base` wildcard host.
    Wildcard(&'a str),
    /// The catch-all (host-less) domain: also the TLS default.
    Default,
}

fn classify(host: Option<&str>) -> Slot<'_> {
    match host {
        Some(h) => match h.strip_prefix("*.") {
            Some(base) => Slot::Wildcard(base),
            None => Slot::Exact(h),
        },
        None => Slot::Default,
    }
}

/// SNI → `ServerConfig` map with huginn's `exact → wildcard → catch-all` +
/// `sni_strict` resolution. Swapped atomically by the proxy on hot-reload.
pub struct ServerCryptoMap {
    exact: HashMap<String, Arc<ServerConfig>>,
    /// Keyed by base domain (e.g. `"example.com"` for `"*.example.com"`).
    wildcard: HashMap<String, Arc<ServerConfig>>,
    /// Catch-all (host-less) domain's config, served for no-SNI / unmatched SNI in
    /// lenient mode. `None` or `sni_strict` disables the fallback.
    default: Option<Arc<ServerConfig>>,
    /// Sentinel config whose resolver returns `None`; handed to the accept path so
    /// rustls emits `unrecognized_name` for the strict / no-match case.
    reject: Arc<ServerConfig>,
    sni_strict: bool,
}

impl std::fmt::Debug for ServerCryptoMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerCryptoMap")
            .field("exact_domains", &self.exact.len())
            .field("wildcard_domains", &self.wildcard.len())
            .field("has_default", &self.default.is_some())
            .field("sni_strict", &self.sni_strict)
            .finish()
    }
}

impl ServerCryptoMap {
    fn place(&mut self, slot: &Slot<'_>, config: Arc<ServerConfig>) {
        match *slot {
            Slot::Exact(h) => {
                self.exact.insert(h.to_string(), config);
            }
            Slot::Wildcard(base) => {
                self.wildcard.insert(base.to_string(), config);
            }
            Slot::Default => self.default = Some(config),
        }
    }

    /// Config currently in `slot` (used to carry a domain's previously serving
    /// config forward when its new cert fails to load).
    fn get(&self, slot: &Slot<'_>) -> Option<Arc<ServerConfig>> {
        match *slot {
            Slot::Exact(h) => self.exact.get(h).map(Arc::clone),
            Slot::Wildcard(base) => self.wildcard.get(base).map(Arc::clone),
            Slot::Default => self.default.clone(),
        }
    }

    /// Resolve `sni` (or no SNI = `None`) to a `ServerConfig`.
    ///
    /// Order: exact → wildcard (one label stripped) → catch-all default. `None` means
    /// no match: in strict mode an unmatched or absent SNI resolves to nothing; in
    /// lenient mode both fall back to the default cert if one exists. A `None` result
    /// tells the accept path to use [`reject_config`](Self::reject_config).
    pub fn select(&self, sni: Option<&str>) -> Option<Arc<ServerConfig>> {
        let Some(sni) = sni else {
            if self.sni_strict {
                return None;
            }
            return self.default.clone();
        };

        if let Some(config) = self.exact.get(sni) {
            return Some(Arc::clone(config));
        }

        // Wildcard: strip the leftmost label. `*.example.com` matches `a.example.com`
        // but NOT `a.b.example.com`.
        if let Some(dot) = sni.find('.') {
            let base = &sni[dot.saturating_add(1)..];
            if let Some(config) = self.wildcard.get(base) {
                return Some(Arc::clone(config));
            }
        }

        if self.sni_strict {
            return None;
        }
        self.default.clone()
    }

    /// The reject sentinel config: hand this to the accept path when
    /// [`select`](Self::select) returns `None` so rustls emits `unrecognized_name`.
    pub fn reject_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.reject)
    }

    /// `true` when at least one domain's config is live (exact, wildcard, or default).
    /// When `false` in HTTPS mode, every handshake is rejected.
    pub fn has_serviceable_config(&self) -> bool {
        !self.exact.is_empty() || !self.wildcard.is_empty() || self.default.is_some()
    }

    /// Test-only snapshot: `(exact_count, wildcard_count, has_default)`.
    #[doc(hidden)]
    pub fn config_summary(&self) -> (usize, usize, bool) {
        (self.exact.len(), self.wildcard.len(), self.default.is_some())
    }

    /// Test-only: does an SNI (or no SNI = `None`) resolve to a config?
    #[doc(hidden)]
    pub fn resolves_for(&self, sni: Option<&str>) -> bool {
        self.select(sni).is_some()
    }
}

/// Build the aws-lc-rs crypto provider, overriding the cipher-suite list only when
/// the config specifies one. Key-exchange groups stay at the provider defaults
/// (which include the post-quantum hybrid group).
fn build_provider(options: &TlsBuildOptions) -> Arc<CryptoProvider> {
    let provider = if options.cipher_suites.is_empty() {
        aws_lc_rs::default_provider()
    } else {
        CryptoProvider {
            cipher_suites: resolve_cipher_suites(&options.cipher_suites),
            ..aws_lc_rs::default_provider()
        }
    };
    Arc::new(provider)
}

/// Build the reject sentinel config (resolver returns `None`).
fn build_reject_config(provider: &Arc<CryptoProvider>) -> Result<Arc<ServerConfig>, CertError> {
    let config = ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| CertError::ServerConfig {
            label: "_reject_".to_string(),
            message: e.to_string(),
        })?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(RejectResolver));
    Ok(Arc::new(config))
}

/// Build one domain's `ServerConfig` from its material, returning it with the cert
/// chain hash. mTLS domains get a client verifier and no resumption; others get the
/// shared ticketer (when resumption is enabled).
async fn build_entry_config(
    entry: &CertEntry,
    options: &TlsBuildOptions,
    provider: &Arc<CryptoProvider>,
    ticketer: Option<&Arc<dyn ProducesTickets>>,
) -> Result<(Arc<ServerConfig>, u64), CertError> {
    let label = entry.label.as_str();
    let material = entry.source.read().await?;
    let (certified_key, cert_hash) = build_certified_key(&material, label)?;

    let builder = ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| CertError::ServerConfig {
            label: label.to_string(),
            message: e.to_string(),
        })?;

    let mut config = if material.is_mutual_tls() {
        let mut roots = RootCertStore::empty();
        for ca in material.client_ca_certs.iter().flatten() {
            roots.add(ca.clone()).map_err(|e| CertError::ServerConfig {
                label: label.to_string(),
                message: e.to_string(),
            })?;
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider))
                .build()
                .map_err(|e| CertError::ServerConfig {
                    label: label.to_string(),
                    message: e.to_string(),
                })?;
        builder
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(SingleCertResolver(certified_key)))
    } else {
        builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertResolver(certified_key)))
    };

    if !options.alpn.is_empty() {
        config.alpn_protocols = options.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }

    // Stateless tickets only: never a server-side cache. mTLS domains get neither, so
    // the client cert is verified on every connection (no resumption bypass).
    config.session_storage = Arc::new(NoServerSessionStorage {});
    if !material.is_mutual_tls() {
        if let Some(ticketer) = ticketer {
            config.ticketer = Arc::clone(ticketer);
        }
    }

    Ok((Arc::new(config), cert_hash))
}

/// Build a [`ServerCryptoMap`] from `entries`.
///
/// Best-effort, per-domain: a domain whose cert fails to load does not abort the
/// build. When `previous` is `Some`, a failing domain keeps its previously serving
/// config (carried over from the old map) so a bad file mid-rotation never takes it
/// offline. The returned [`CertReloadReport`] lists which configs loaded (with their
/// chain hash) vs. which failed; a non-empty `failed` is a partial build.
///
/// Returns `Err` only for process-wide setup that fails before any domain is built
/// (ticketer or provider/version setup); per-domain failures are reported, not fatal.
pub async fn build_server_crypto(
    entries: &[CertEntry],
    options: &TlsBuildOptions,
    previous: Option<&ServerCryptoMap>,
) -> Result<(ServerCryptoMap, CertReloadReport), CertError> {
    let provider = build_provider(options);
    let ticketer = if options.resumption_enabled {
        Some(shared_ticketer()?)
    } else {
        None
    };
    let reject = build_reject_config(&provider)?;

    let mut map = ServerCryptoMap {
        exact: HashMap::new(),
        wildcard: HashMap::new(),
        default: None,
        reject,
        sni_strict: options.sni_strict,
    };
    let mut loaded: Vec<(String, u64)> = Vec::new();
    let mut failed: Vec<String> = Vec::new();

    for entry in entries {
        let label = entry.label.as_str();
        let slot = classify(entry.host.as_deref());
        match build_entry_config(entry, options, &provider, ticketer.as_ref()).await {
            Ok((config, cert_hash)) => {
                map.place(&slot, config);
                loaded.push((label.to_string(), cert_hash));
            }
            Err(e) => {
                failed.push(label.to_string());
                match previous.and_then(|prev| prev.get(&slot)) {
                    Some(prev_config) => {
                        info!(host = label, error = %e, "Cert load failed; keeping previously loaded ServerConfig");
                        map.place(&slot, prev_config);
                    }
                    None => {
                        info!(host = label, error = %e, "Cert load failed; domain has no previous config and will not serve TLS");
                    }
                }
            }
        }
    }

    Ok((map, CertReloadReport { loaded, failed }))
}
