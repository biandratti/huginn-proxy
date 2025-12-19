#![forbid(unsafe_code)]

use dashmap::DashMap;
use std::{
    fmt,
    net::SocketAddr,
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::net::lookup_host;
use tracing::{debug, trace, warn};

const DNS_CACHE_MIN_TTL: Duration = Duration::from_secs(30);
const DNS_CACHE_MAX_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Socket(SocketAddr),
    Domain(String, u16),
}

#[derive(Debug, Clone)]
struct CacheEntry {
    addresses: Vec<SocketAddr>,
    expires_at: Instant,
}

impl CacheEntry {
    fn new(addresses: Vec<SocketAddr>, expires_at: Instant) -> Self {
        Self { addresses, expires_at }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

#[derive(Debug)]
pub struct DnsCache {
    entries: DashMap<String, CacheEntry>,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DNS_CACHE_MIN_TTL, DNS_CACHE_MAX_TTL)
    }
}

impl DnsCache {
    pub fn new(min_ttl: Duration, max_ttl: Duration) -> Self {
        Self { entries: DashMap::new(), min_ttl, max_ttl }
    }

    pub async fn get_or_resolve(&self, domain: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        if let Some(entry) = self.entries.get(domain) {
            let snapshot = entry.value().clone();
            drop(entry);
            if !snapshot.is_expired() {
                debug!("DNS cache hit for domain: {}", domain);
                return Ok(snapshot.addresses);
            }
        }

        match self.resolve_and_cache(domain, port).await {
            Ok(addresses) => Ok(addresses),
            Err(e) => {
                if let Some(entry) = self.entries.get(domain) {
                    warn!("DNS resolve failed for {domain}, using stale cache: {e}");
                    return Ok(entry.addresses.clone());
                }
                Err(e)
            }
        }
    }

    async fn resolve_and_cache(&self, domain: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        debug!("Resolving DNS for: {}", domain);
        let lookup = lookup_host((domain, port))
            .await
            .map_err(|e| format!("failed to resolve {domain}: {e}"))?;
        let addresses: Vec<SocketAddr> = lookup.collect();
        if addresses.is_empty() {
            return Err(format!("no addresses found for {domain}"));
        }
        // Without TTL info from std lookup, apply bounds directly using clamp.
        let expires_at = self.clamp_ttl(
            Instant::now()
                .checked_add(self.max_ttl)
                .unwrap_or_else(Instant::now),
        );

        let entry = CacheEntry::new(addresses.clone(), expires_at);
        self.entries.insert(domain.to_string(), entry);

        trace!("cache updated for {domain}: {:?}", addresses);
        Ok(addresses)
    }

    fn clamp_ttl(&self, expires_at: Instant) -> Instant {
        let ttl = expires_at.saturating_duration_since(Instant::now());
        let clamped = if ttl < self.min_ttl {
            self.min_ttl
        } else if ttl > self.max_ttl {
            self.max_ttl
        } else {
            ttl
        };
        Instant::now()
            .checked_add(clamped)
            .unwrap_or_else(Instant::now)
    }
}

impl TargetAddr {
    fn validate_domain(domain: &str) -> bool {
        !domain.is_empty()
            && domain.len() <= 253
            && domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !domain.contains("..")
    }

    pub async fn resolve_cached(&self, cache: &DnsCache) -> Result<Vec<SocketAddr>, String> {
        match self {
            TargetAddr::Socket(addr) => Ok(vec![*addr]),
            TargetAddr::Domain(domain, port) => cache.get_or_resolve(domain, *port).await,
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Socket(addr) => write!(f, "{addr}"),
            TargetAddr::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

impl FromStr for TargetAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            return Ok(TargetAddr::Socket(socket_addr));
        }

        let (domain, port) = s
            .rsplit_once(':')
            .ok_or_else(|| "missing port number".to_string())?;

        if !Self::validate_domain(domain) {
            return Err("invalid domain name".to_string());
        }

        let port = port
            .parse::<u16>()
            .map_err(|_| "invalid port number".to_string())?;

        Ok(TargetAddr::Domain(domain.to_string(), port))
    }
}
