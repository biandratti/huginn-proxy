use std::sync::Arc;
use tokio_rustls::rustls::server::{
    ProducesTickets, ServerSessionMemoryCache, StoresServerSessions,
};
use tokio_rustls::rustls::ServerConfig;

use crate::config::SessionResumptionConfig;

/// Configures session resumption in ServerConfig
///
/// This function configures BOTH TLS 1.2 and TLS 1.3 session resumption:
/// - TLS 1.2 uses `session_storage` (ServerSessionMemoryCache) - requires server-side storage
/// - TLS 1.3 uses `ticketer` (ProducesTickets) - stateless, client stores tickets
///
/// Rustls automatically selects the appropriate mechanism based on the negotiated TLS version.
/// A single ServerConfig can handle both versions simultaneously.
///
/// We use rustls defaults for TLS 1.3 ticketer (no explicit configuration).
/// We only configure TLS 1.2 session storage with a configurable cache size.
/// For TLS 1.3: we leave rustls default ticketer unchanged
/// TLS 1.2 requires server-side storage to remember session IDs
pub fn configure_session_resumption(server: &mut ServerConfig, config: &SessionResumptionConfig) {
    if !config.enabled {
        // Disable session resumption for both TLS 1.2 and 1.3
        server.session_storage = Arc::new(NoSessionStorage);
        server.ticketer = Arc::new(NoTicketProducer);
        return;
    }

    let cache = ServerSessionMemoryCache::new(config.max_sessions);
    server.session_storage = cache;
}

// Implementations to disable session resumption

/// No-op session storage that disables TLS 1.2 session ID resumption
#[derive(Debug)]
struct NoSessionStorage;

impl StoresServerSessions for NoSessionStorage {
    fn put(&self, _key: Vec<u8>, _value: Vec<u8>) -> bool {
        false
    }

    fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn take(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn can_cache(&self) -> bool {
        false
    }
}

/// No-op ticket producer that disables TLS 1.3 session tickets
#[derive(Debug)]
struct NoTicketProducer;

impl ProducesTickets for NoTicketProducer {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}
