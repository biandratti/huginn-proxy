use std::sync::Arc;
use tokio::sync::watch;

use crate::config::{
    Backend, IpFilterConfig, KeepAliveConfig, RateLimitConfig, Route, SecurityHeaders,
};
use crate::security::RateLimitManager;
use crate::telemetry::Metrics;

/// Security-related context for request handling
#[derive(Clone)]
pub struct SecurityContext {
    pub headers: SecurityHeaders,
    pub ip_filter: IpFilterConfig,
    pub rate_limit_config: RateLimitConfig,
    pub rate_limit_manager: Option<Arc<RateLimitManager>>,
}

impl SecurityContext {
    pub fn new(
        headers: SecurityHeaders,
        ip_filter: IpFilterConfig,
        rate_limit_config: RateLimitConfig,
        rate_limit_manager: Option<Arc<RateLimitManager>>,
    ) -> Self {
        Self { headers, ip_filter, rate_limit_config, rate_limit_manager }
    }
}

/// Request handling context
pub struct RequestContext {
    pub routes: Vec<Route>,
    pub backends: Arc<Vec<Backend>>,
    pub tls_header: Option<hyper::header::HeaderValue>,
    pub fingerprint_rx: Option<watch::Receiver<Option<huginn_net_http::AkamaiFingerprint>>>,
    pub keep_alive: KeepAliveConfig,
    pub security: SecurityContext,
    pub metrics: Option<Arc<Metrics>>,
    pub peer: std::net::SocketAddr,
    pub is_https: bool,
}
