use std::sync::Arc;

use tokio::sync::watch;
use tokio_rustls::rustls::server::ResolvesServerCert;

use crate::proxy::shutdown::ServiceHandle;

pub struct AcmeRuntime {
    /// `(exact host, resolver)` per ACME domain; used to build the [`crate::tls::CompositeResolver`]'s
    /// SNI routing table. Hosts are matched case-insensitively (the composite lowercases them).
    pub resolvers: Vec<(String, Arc<dyn ResolvesServerCert>)>,
    /// Background issuance/renewal tasks, already wrapped for ordered cooperative shutdown.
    pub tasks: Vec<ServiceHandle>,
    /// Fires `true` once the first ACME certificate is deployed (new issuance or cached load).
    /// When `Some`, [`super::server::run`] holds the proxy in not-ready state until the signal
    /// arrives or the startup timeout elapses, preventing the LB from routing traffic before a
    /// cert exists. Set to `None` if readiness gating is not needed (e.g. tests).
    pub cert_ready_rx: Option<watch::Receiver<bool>>,
}
