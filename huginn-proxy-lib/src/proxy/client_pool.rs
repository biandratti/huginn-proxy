use crate::config::{BackendPoolConfig, KeepAliveConfig};
use http::Version;
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use std::time::Duration;

pub type HttpClient = Client<HttpConnector, Incoming>;

/// Shared HTTP client pool for backend connections
///
/// This pool maintains reusable HTTP/1.1 and HTTP/2 clients to avoid
/// creating new TCP and TLS connections for every request.
///
/// # Performance Impact
///
/// - **With pooling**: Request latency = Processing time (~10-50ms)
/// - **Without pooling**: Request latency = TCP handshake (~1-5ms) + TLS handshake (~50-200ms) + Processing (~10-50ms)
///
/// # Force New Connection
///
/// Routes can bypass pooling by setting `force_new_connection = true`.
/// Use cases:
/// - TCP fingerprinting (future feature)
/// - Per-request TLS fingerprinting
/// - Testing/debugging connection behavior
#[derive(Clone)]
pub struct ClientPool {
    /// Client for HTTP/1.1 requests (supports keep-alive and pooling)
    http11: Arc<HttpClient>,

    /// Client for HTTP/2 requests (http2_only with pooling)
    http2: Arc<HttpClient>,

    /// Configuration (stored for creating one-off clients)
    keep_alive: KeepAliveConfig,

    /// Pool configuration
    #[allow(dead_code)]
    config: BackendPoolConfig,
}

impl ClientPool {
    /// Create a new client pool with the given configuration
    pub fn new(keep_alive: &KeepAliveConfig, config: BackendPoolConfig) -> Self {
        let http11_client = Self::create_http11_client(keep_alive, &config);
        let http2_client = Self::create_http2_client(keep_alive, &config);

        Self {
            http11: Arc::new(http11_client),
            http2: Arc::new(http2_client),
            keep_alive: keep_alive.clone(),
            config,
        }
    }

    /// Create HTTP/1.1 client with keep-alive and pooling support
    fn create_http11_client(
        keep_alive: &KeepAliveConfig,
        config: &BackendPoolConfig,
    ) -> HttpClient {
        let mut connector = HttpConnector::new();
        // TCP keep-alive: sends periodic packets to keep TCP connection alive
        if keep_alive.enabled {
            connector.set_keepalive(Some(Duration::from_secs(keep_alive.timeout_secs)));
        } else {
            connector.set_keepalive(None);
        }

        let mut builder = Client::builder(TokioExecutor::new());
        builder.pool_idle_timeout(Duration::from_secs(config.idle_timeout));

        // Configure connection pool settings
        if config.pool_max_idle_per_host > 0 {
            builder.pool_max_idle_per_host(config.pool_max_idle_per_host);
        }

        builder.build(connector)
    }

    /// Create HTTP/2-only client with keep-alive and pooling support
    fn create_http2_client(keep_alive: &KeepAliveConfig, config: &BackendPoolConfig) -> HttpClient {
        let mut connector = HttpConnector::new();
        // TCP keep-alive: sends periodic packets to keep TCP connection alive
        // HTTP/2 uses persistent connections by default with native multiplexing
        if keep_alive.enabled {
            connector.set_keepalive(Some(Duration::from_secs(keep_alive.timeout_secs)));
        } else {
            connector.set_keepalive(None);
        }

        let mut builder = Client::builder(TokioExecutor::new());
        builder.http2_only(true);
        builder.pool_idle_timeout(Duration::from_secs(config.idle_timeout));

        // Configure connection pool settings
        if config.pool_max_idle_per_host > 0 {
            builder.pool_max_idle_per_host(config.pool_max_idle_per_host);
        }

        builder.build(connector)
    }

    /// Get the appropriate client for the given HTTP version
    ///
    /// Returns `None` if `force_new` is true, signaling that the caller should
    /// create a one-off client instead of using the pool.
    ///
    /// # Arguments
    ///
    /// * `version` - Target HTTP version
    /// * `force_new` - If true, bypass pooling and return None
    ///
    /// # Returns
    ///
    /// - `Some(&Arc<HttpClient>)` - Pooled client to use
    /// - `None` - Create one-off client via `create_oneoff_client()`
    pub fn get_client(&self, version: Version, force_new: bool) -> Option<&Arc<HttpClient>> {
        if force_new {
            None // Signal to create a one-off client
        } else {
            Some(match version {
                Version::HTTP_2 => &self.http2,
                _ => &self.http11,
            })
        }
    }

    /// Create a one-off client for `force_new_connection` scenarios
    ///
    /// This client will NOT pool connections. Each request will establish
    /// a new TCP connection and TLS handshake.
    ///
    /// # Use Cases
    ///
    /// - TCP fingerprinting (future feature)
    /// - Per-request TLS fingerprinting
    /// - Testing/debugging connection behavior
    ///
    /// # Performance Warning
    ///
    /// Creating a new client per request adds 51-205ms of latency
    /// (TCP handshake + TLS handshake). Only use when necessary.
    pub fn create_oneoff_client(&self, version: Version) -> HttpClient {
        // For one-off clients, disable pooling by setting max idle to 0
        let oneoff_config =
            BackendPoolConfig { enabled: false, idle_timeout: 0, pool_max_idle_per_host: 0 };

        match version {
            Version::HTTP_2 => Self::create_http2_client(&self.keep_alive, &oneoff_config),
            _ => Self::create_http11_client(&self.keep_alive, &oneoff_config),
        }
    }
}
