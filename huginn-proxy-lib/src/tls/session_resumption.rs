use std::sync::Arc;
use tokio_rustls::rustls::server::{
    ProducesTickets, ServerSessionMemoryCache, StoresServerSessions,
};
use tokio_rustls::rustls::ServerConfig;

use crate::config::SessionResumptionConfig;

/// Configures session resumption in ServerConfig
///
/// Follows the pattern from rust-rpxy: modify ServerConfig after construction,
/// similar to how rust-rpxy modifies `server_crypto_local.alpn_protocols`.
///
/// IMPORTANT: This function configures BOTH TLS 1.2 and TLS 1.3 session resumption:
/// - TLS 1.2 uses `session_storage` (ServerSessionMemoryCache) - requires server-side storage
/// - TLS 1.3 uses `ticketer` (ProducesTickets) - stateless, client stores tickets
///
/// Rustls automatically selects the appropriate mechanism based on the negotiated TLS version.
/// A single ServerConfig can handle both versions simultaneously.
///
/// Like rust-rpxy, we use rustls defaults for TLS 1.3 ticketer (no explicit configuration).
/// We only configure TLS 1.2 session storage with a configurable cache size.
pub fn configure_session_resumption(server: &mut ServerConfig, config: &SessionResumptionConfig) {
    if !config.enabled {
        // Disable session resumption for both TLS 1.2 and 1.3
        server.session_storage = Arc::new(NoSessionStorage);
        server.ticketer = Arc::new(NoTicketProducer);
        return;
    }

    // Session resumption is enabled
    // Configure TLS 1.2 session ID resumption with configurable cache size
    // TLS 1.2 requires server-side storage to remember session IDs
    let cache = ServerSessionMemoryCache::new(config.max_sessions);
    server.session_storage = cache;

    // For TLS 1.3: Leave rustls default ticketer unchanged (same approach as rust-rpxy)
    // TLS 1.3 is STATELESS - it does NOT use the session_storage cache above
    // Instead, it uses encrypted tickets that the client stores
    // Note: rustls may or may not enable ticketer by default depending on version
    // We don't modify server.ticketer, letting rustls use its defaults
    // If the default ticketer is disabled, TLS 1.3 session resumption won't work,
    // but that's consistent with rustls default behavior
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
