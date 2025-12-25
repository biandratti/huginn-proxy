#![forbid(unsafe_code)]

use std::sync::Arc;

use config::{Config, Route, TlsConfig};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use http::StatusCode;
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, ServerConfig as RustlsServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

pub mod config;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

type HttpClient = Client<HttpConnector, Incoming>;
type RespBody = BoxBody<bytes::Bytes, hyper::Error>;

fn empty_body() -> RespBody {
    Full::new(bytes::Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

fn bad_gateway() -> Response<RespBody> {
    let mut resp = Response::new(empty_body());
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    resp
}

fn build_rustls(cfg: &TlsConfig) -> Result<TlsAcceptor, BoxError> {
    let certs = {
        let bytes = std::fs::read(&cfg.cert_path)?;
        let mut reader = std::io::BufReader::new(&bytes[..]);
        rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?
    };
    let key = {
        let bytes = std::fs::read(&cfg.key_path)?;
        let mut reader = std::io::BufReader::new(&bytes[..]);
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader).collect::<Result<Vec<_>, _>>()?;
        let Some(k) = keys.pop() else {
            return Err("no private key found".into());
        };
        rustls::pki_types::PrivateKeyDer::Pkcs8(k)
    };
    let mut server = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    if !cfg.alpn.is_empty() {
        server.alpn_protocols = cfg.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    } else {
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    Ok(TlsAcceptor::from(Arc::new(server)))
}

fn pick_route<'a>(path: &str, routes: &'a [Route]) -> Option<&'a str> {
    routes.iter().find(|r| path.starts_with(&r.prefix)).map(|r| r.backend.as_str())
}

async fn forward(req: Request<Incoming>, client: HttpClient, backend: String) -> Result<Response<RespBody>, BoxError> {
    let uri = format!(
        "http://{}{}",
        backend,
        req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("")
    )
    .parse()?;
    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    let out_req = Request::from_parts(parts, body);
    let resp = client.request(out_req).await?;
    Ok(resp.map(|b| b.boxed()))
}

pub async fn run(config: Arc<Config>) -> Result<(), BoxError> {
    let addr = config.listen;
    let listener = TcpListener::bind(addr).await?;
    let connector = HttpConnector::new();
    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder.http2_only(true);
    let client: HttpClient = client_builder.build(connector);
    let builder = ConnBuilder::new(TokioExecutor::new());
    let backends = config.backends.clone();
    let routes = config.routes.clone();
    let tls_acceptor = match &config.tls {
        Some(t) => Some(build_rustls(t)?),
        None => None,
    };
    let rr_idx = Arc::new(tokio::sync::Mutex::new(0usize));

    info!(?addr, "starting L7 proxy (h1/h2)");
    loop {
        let (stream, peer) = listener.accept().await?;
        let client = client.clone();
        let builder = builder.clone();
        let backend_list = backends.clone();
        let routes = routes.clone();
        let rr_idx = rr_idx.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let client = client.clone();
                let routes = routes.clone();
                let backend_list = backend_list.clone();
                let rr_idx = rr_idx.clone();
                async move {
                    // routing by prefix
                    let path = req.uri().path();
                    let backend = if let Some(target) = pick_route(path, &routes) {
                        target.to_string()
                    } else {
                        if backend_list.is_empty() {
                            let resp = bad_gateway();
                            return Ok::<_, hyper::Error>(resp);
                        }
                        let mut guard = rr_idx.lock().await;
                        let len = backend_list.len();
                        let g = *guard;
                        let idx = g.checked_rem(len).unwrap_or(0);
                        *guard = guard.wrapping_add(1);
                        backend_list[idx].address.clone()
                    };

                    match forward(req, client, backend).await {
                        Ok(resp) => Ok::<_, hyper::Error>(resp),
                        Err(_) => {
                            let resp = bad_gateway();
                            Ok::<_, hyper::Error>(resp)
                        }
                    }
                }
            });

            // TLS if configured
            if let Some(acc) = tls_acceptor {
                match acc.accept(stream).await {
                    Ok(tls) => {
                        if let Err(e) = builder.serve_connection(TokioIo::new(tls), svc).await {
                            warn!(?peer, error = %e, "serve_connection error");
                        }
                    }
                    Err(e) => {
                        warn!(?peer, error = %e, "tls accept error");
                    }
                }
            } else if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                warn!(?peer, error = %e, "serve_connection error");
            }
        });
    }
}
