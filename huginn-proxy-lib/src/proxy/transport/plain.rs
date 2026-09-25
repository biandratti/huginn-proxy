use std::sync::Arc;

use super::timeout_helper::serve_with_timeout;
use crate::backend::UpstreamGateway;
use crate::fingerprinting::{CapturingStream, ConnectionFingerprints, TcpObservation};
use crate::proxy::ClientPool;
use crate::proxy::handler::request::handle_proxy_request;
use crate::proxy::synthetic_response::synthetic_error_response;
use crate::telemetry::Metrics;
use http::StatusCode;
use huginn_net_http::AkamaiFingerprint;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;

/// Configuration for handling plain HTTP connections
pub struct PlainConnectionConfig {
    pub fingerprint_config: crate::config::FingerprintConfig,
    pub domains: Arc<Vec<crate::config::Domain>>,
    pub backends: Arc<Vec<crate::config::Backend>>,
    pub keep_alive: crate::config::KeepAliveConfig,
    pub security: crate::proxy::SecurityContext,
    pub metrics: Arc<Metrics>,
    pub builder: ConnBuilder<TokioExecutor>,
    pub preserve_host: bool,
    pub connection_handling_timeout: tokio::time::Duration,
    pub client_pool: Arc<ClientPool>,
    pub syn_fingerprint: Option<TcpObservation>,
    pub upstream: UpstreamGateway,
    pub shutdown_rx: crate::proxy::shutdown::ShutdownWatch,
    pub listen: crate::config::RuntimeListen,
}

/// Handle a plain HTTP connection
pub async fn handle_plain_connection(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    config: PlainConnectionConfig,
) {
    // JA4 needs a ClientHello, so it stays `None` on this transport; Akamai is captured
    // from the HTTP/2 frames exactly as on the TLS path (cleartext h2 is prior knowledge).
    let mut fingerprints =
        ConnectionFingerprints { tcp_syn: config.syn_fingerprint.clone(), ..Default::default() };

    if config.fingerprint_config.http_enabled {
        let (akamai_tx, akamai_rx) = watch::channel(None::<AkamaiFingerprint>);
        let (capturing_stream, _extracted) = CapturingStream::new(
            stream,
            config.fingerprint_config.max_capture,
            akamai_tx,
            Arc::clone(&config.metrics),
        );
        fingerprints.akamai = Some(akamai_rx);
        serve_plain(capturing_stream, fingerprints, peer, config).await;
    } else {
        serve_plain(stream, fingerprints, peer, config).await;
    }
}

async fn serve_plain<S>(
    stream: S,
    fingerprints: ConnectionFingerprints,
    peer: std::net::SocketAddr,
    config: PlainConnectionConfig,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let backends = config.backends.clone();
    let metrics = config.metrics.clone();
    let domains = config.domains.clone();
    let keep_alive = config.keep_alive.clone();
    let security = config.security.clone();
    let client_pool = config.client_pool.clone();
    let upstream = config.upstream.clone();

    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let domains = domains.clone();
        let backends = backends.clone();
        let metrics = metrics.clone();
        let keep_alive = keep_alive.clone();
        let security = security.clone();
        let client_pool = client_pool.clone();
        let upstream = upstream.clone();
        let listen = config.listen;
        let fingerprints = fingerprints.clone();

        async move {
            let preserve_host = config.preserve_host;
            let http_result = handle_proxy_request(
                req,
                domains,
                backends,
                fingerprints,
                &keep_alive,
                &security,
                &metrics,
                peer,
                false,
                preserve_host,
                &client_pool,
                &upstream,
                None,
                listen,
            )
            .await;

            match http_result {
                Ok(v) => Ok::<_, hyper::Error>(v),
                Err(e) => {
                    e.log_with_peer(peer);
                    let code = StatusCode::from(e.clone());
                    metrics.record_error(e.error_type());
                    match synthetic_error_response(code) {
                        Ok(resp) => Ok(resp),
                        Err(e) => Ok(crate::utils::http::json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("Failed to create error response: {e}"),
                        )),
                    }
                }
            }
        }
    });

    let serve_fut = Box::pin(
        config
            .builder
            .serve_connection(TokioIo::new(stream), svc)
            .into_owned(),
    );

    serve_with_timeout(
        serve_fut,
        config.connection_handling_timeout,
        config.shutdown_rx,
        &config.metrics,
        peer,
    )
    .await;
}
