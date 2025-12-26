#![forbid(unsafe_code)]

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use config::{Config, Route, TlsConfig};
use http::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
use huginn_net_http::http2_parser::{Http2Parser, HTTP2_CONNECTION_PREFACE};
use huginn_net_tls::tls_process::parse_tls_client_hello;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, ServerConfig as RustlsServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

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

fn tls_header_value<IO>(
    ja4: &Option<String>,
    tls: &tokio_rustls::server::TlsStream<IO>,
) -> Option<HeaderValue>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let conn = tls.get_ref().1;
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_else(|| "-".to_string());
    let mut parts = Vec::new();
    if let Some(f) = ja4 {
        parts.push(format!("ja4={f}"));
    }
    parts.push(format!("alpn={alpn}"));
    HeaderValue::from_str(&parts.join(";")).ok()
}

fn http_header_value(akamai: &Option<String>) -> Option<HeaderValue> {
    let mut parts = Vec::new();
    if let Some(f) = akamai {
        parts.push(format!("akamai={f}"));
    } else {
        parts.push("akamai=-".to_string());
    }
    HeaderValue::from_str(&parts.join(";")).ok()
}

struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, offset: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.offset = self.offset.saturating_add(to_copy);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// CapturingStream captures all data read from the inner stream
/// while passing it through, similar to how fingerproxy captures HTTP/2 frames
struct CapturingStream<S> {
    inner: S,
    captured: Arc<Mutex<Vec<u8>>>,
    fingerprint_result: Arc<Mutex<Option<String>>>,
    max_capture: usize,
}

impl<S> CapturingStream<S> {
    #[allow(clippy::type_complexity)] //TODO
    fn new(
        inner: S,
        max_capture: usize,
    ) -> (Self, Arc<Mutex<Vec<u8>>>, Arc<Mutex<Option<String>>>) {
        let captured = Arc::new(Mutex::new(Vec::with_capacity(8192))); //TODO
        let captured_clone = captured.clone();
        let fingerprint_result = Arc::new(Mutex::new(None));
        let fingerprint_result_clone = fingerprint_result.clone();
        (
            Self { inner, captured, fingerprint_result, max_capture },
            captured_clone,
            fingerprint_result_clone,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CapturingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();

        // Capture the data that was read and try to extract fingerprint immediately
        if after > before {
            let read_data = &buf.filled()[before..after];
            debug!("CapturingStream: read {} bytes", read_data.len());
            if let Ok(mut captured) = self.captured.lock() {
                let old_len = captured.len();
                if captured.len() < self.max_capture {
                    let remaining = self.max_capture.saturating_sub(captured.len());
                    let to_capture = read_data.len().min(remaining);
                    captured.extend_from_slice(&read_data[..to_capture]);
                    debug!(
                        "CapturingStream: captured {} bytes (total: {})",
                        to_capture,
                        captured.len()
                    );

                    // Try to extract fingerprint immediately if we have enough data
                    // and haven't extracted it yet
                    let has_fingerprint = self
                        .fingerprint_result
                        .lock()
                        .ok()
                        .and_then(|r| r.clone())
                        .is_some();
                    if !has_fingerprint {
                        // Skip HTTP/2 connection preface if present
                        let frame_data = if captured.starts_with(HTTP2_CONNECTION_PREFACE) {
                            debug!(
                                "CapturingStream: skipping HTTP/2 connection preface (24 bytes)"
                            );
                            &captured[HTTP2_CONNECTION_PREFACE.len()..]
                        } else {
                            &captured
                        };

                        if frame_data.len() >= 9 {
                            debug!("CapturingStream: attempting to parse {} bytes for fingerprint (after skipping preface)", frame_data.len());
                            let parser = Http2Parser::new();
                            match parser.parse_frames(frame_data) {
                                Ok(frames) => {
                                    debug!("CapturingStream: parsed {} frames", frames.len());
                                    if let Some(fingerprint) = extract_akamai_fingerprint(&frames) {
                                        debug!(
                                            "CapturingStream: extracted fingerprint: {}",
                                            fingerprint.fingerprint
                                        );
                                        if let Ok(mut result) = self.fingerprint_result.lock() {
                                            *result = Some(fingerprint.fingerprint);
                                        }
                                    } else {
                                        debug!(
                                            "CapturingStream: no fingerprint extracted from frames"
                                        );
                                    }
                                }
                                Err(e) => {
                                    debug!("CapturingStream: failed to parse frames: {:?}", e);
                                }
                            }
                        } else {
                            debug!(
                                "CapturingStream: not enough data yet ({} < 9, total captured: {})",
                                frame_data.len(),
                                captured.len()
                            );
                        }
                    } else {
                        debug!("CapturingStream: fingerprint already extracted, skipping");
                    }
                } else {
                    debug!("CapturingStream: max capture reached ({}), skipping", old_len);
                }
            }
        }

        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CapturingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn read_client_hello(
    stream: &mut tokio::net::TcpStream,
) -> std::io::Result<(Vec<u8>, Option<String>)> {
    let mut buf = Vec::with_capacity(8192);
    loop {
        if buf.len() >= 5 {
            let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let needed = len.saturating_add(5);
            if buf.len() >= needed {
                break;
            }
        }
        let read = stream.read_buf(&mut buf).await?;
        if read == 0 {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }

    let ja4 = parse_tls_client_hello(&buf)
        .ok()
        .map(|sig| sig.generate_ja4().full.value().to_string());

    Ok((buf, ja4))
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
        let mut keys =
            rustls_pemfile::pkcs8_private_keys(&mut reader).collect::<Result<Vec<_>, _>>()?;
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
    routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
        .map(|r| r.backend.as_str())
}

async fn forward(
    req: Request<Incoming>,
    client: HttpClient,
    backend: String,
) -> Result<Response<RespBody>, BoxError> {
    let uri = format!(
        "http://{}{}",
        backend,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("")
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
            let mut stream = stream;
            // TLS if configured
            if let Some(acc) = tls_acceptor {
                let (prefix, ja4) = match read_client_hello(&mut stream).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(?peer, error = %e, "failed to read client hello");
                        return;
                    }
                };
                let prefixed = PrefixedStream::new(prefix, stream);
                match acc.accept(prefixed).await {
                    Ok(tls) => {
                        let tls_header = tls_header_value(&ja4, &tls);

                        // Use CapturingStream to capture HTTP/2 frames while hyper reads them
                        // Similar to how fingerproxy captures frames during HTTP/2 handshake
                        // The fingerprint is extracted reactively as data is captured, no delays needed
                        let alpn = tls
                            .get_ref()
                            .1
                            .alpn_protocol()
                            .map(|p| String::from_utf8_lossy(p).into_owned())
                            .unwrap_or_else(|| "-".to_string());
                        debug!(?peer, ?alpn, "Creating CapturingStream for HTTP/2 fingerprinting");
                        let (capturing_stream, _captured_buffer, fingerprint_result) =
                            CapturingStream::new(tls, 64 * 1024);
                        let fingerprint_result_for_service = fingerprint_result.clone();
                        let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
                            let client = client.clone();
                            let routes = routes.clone();
                            let backend_list = backend_list.clone();
                            let rr_idx = rr_idx.clone();
                            let tls_header = tls_header.clone();
                            let fingerprint_result = fingerprint_result_for_service.clone();
                            async move {
                                if let Some(hv) = tls_header.clone() {
                                    req.headers_mut()
                                        .insert(HeaderName::from_static("x-huginn-net-tls"), hv);
                                }
                                // Get fingerprint from CapturingStream (extracted reactively as data arrives)
                                let akamai = fingerprint_result.lock().ok().and_then(|r| r.clone());
                                debug!("Handler: akamai fingerprint: {:?}", akamai);
                                if let Some(hv) = http_header_value(&akamai) {
                                    debug!("Handler: injecting x-huginn-net-http header: {:?}", hv);
                                    req.headers_mut()
                                        .insert(HeaderName::from_static("x-huginn-net-http"), hv);
                                } else {
                                    debug!("Handler: no HTTP fingerprint header to inject");
                                }
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

                        if let Err(e) = builder
                            .serve_connection(TokioIo::new(capturing_stream), svc)
                            .await
                        {
                            warn!(?peer, error = %e, "serve_connection error");
                        }
                    }
                    Err(e) => {
                        warn!(?peer, error = %e, "tls accept error");
                    }
                }
            } else {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let client = client.clone();
                    let routes = routes.clone();
                    let backend_list = backend_list.clone();
                    let rr_idx = rr_idx.clone();
                    async move {
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
                if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                    warn!(?peer, error = %e, "serve_connection error");
                }
            }
        });
    }
}
