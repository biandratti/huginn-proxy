use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
use huginn_net_http::http2_parser::Http2Parser;
use huginn_net_http::AkamaiFingerprint;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::debug;

/// CapturingStream captures all data read from the inner stream
/// while passing it through. Processes fingerprint inline for optimal performance
pub struct CapturingStream<S> {
    inner: S,
    fingerprint_tx: watch::Sender<Option<AkamaiFingerprint>>,
    fingerprint_extracted: Arc<AtomicBool>,
    max_capture: usize,
    captured_len: Arc<AtomicUsize>,
    buffer: Vec<u8>, // Inline buffer for fast processing
    parser: Http2Parser<'static>,
    parsed_offset: usize,
    extraction_start: Option<Instant>,
    metrics: Option<Arc<crate::telemetry::Metrics>>,
}

impl<S> CapturingStream<S> {
    pub fn new(
        inner: S,
        max_capture: usize,
        fingerprint_tx: watch::Sender<Option<AkamaiFingerprint>>,
        metrics: Option<Arc<crate::telemetry::Metrics>>,
    ) -> (Self, Arc<AtomicBool>) {
        let fingerprint_extracted = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                fingerprint_tx,
                fingerprint_extracted: fingerprint_extracted.clone(),
                max_capture,
                captured_len: Arc::new(AtomicUsize::new(0)),
                buffer: Vec::with_capacity(max_capture),
                parser: Http2Parser::new(),
                parsed_offset: 0,
                extraction_start: Some(Instant::now()),
                metrics,
            },
            fingerprint_extracted,
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

        if after > before && !self.fingerprint_extracted.load(Ordering::Relaxed) {
            let read_data = &buf.filled()[before..after];
            let current_len = self.captured_len.load(Ordering::Relaxed);

            if current_len < self.max_capture {
                let remaining = self.max_capture.saturating_sub(current_len);
                let to_capture = read_data.len().min(remaining);
                let data_to_process = &read_data[..to_capture];

                self.captured_len
                    .store(current_len.saturating_add(to_capture), Ordering::Relaxed);

                self.buffer.extend_from_slice(data_to_process);

                // Use parse_frames_skip_preface to handle preface automatically
                let frame_data = if self.parsed_offset == 0 {
                    &self.buffer[..]
                } else {
                    &self.buffer[self.parsed_offset..]
                };

                if frame_data.len() >= 9 {
                    // Use parse_frames_skip_preface to get both frames and bytes consumed (handles preface automatically)
                    match self.parser.parse_frames_skip_preface(frame_data) {
                        Ok((frames, bytes_consumed)) => {
                            if !frames.is_empty() {
                                // Update parsed_offset based on actual bytes consumed (includes preface if present)
                                self.parsed_offset =
                                    self.parsed_offset.saturating_add(bytes_consumed);

                                if let Some(fingerprint) = extract_akamai_fingerprint(&frames) {
                                    debug!(
                                        "CapturingStream: extracted fingerprint inline: {}",
                                        fingerprint.fingerprint
                                    );
                                    // Update fingerprint immediately
                                    let _ = self.fingerprint_tx.send(Some(fingerprint));
                                    self.fingerprint_extracted.store(true, Ordering::Relaxed);

                                    let start = self.extraction_start.take();
                                    if let Some(ref m) = &self.metrics {
                                        if let Some(start_time) = start {
                                            let duration = start_time.elapsed().as_secs_f64();
                                            m.http2_fingerprints_extracted_total.add(1, &[]);
                                            m.http2_fingerprint_extraction_duration_seconds
                                                .record(duration, &[]);
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // Parsing error, continue (might need more data)
                            // Note: HTTP/1.1 detection happens in handle_proxy_request
                            // when req.version() != HTTP_2
                        }
                    }
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
        // If connection closes before fingerprint extracted, record failure
        if !self.fingerprint_extracted.load(Ordering::Relaxed) {
            if let Some(ref m) = &self.metrics {
                m.http2_fingerprint_failures_total.add(1, &[]);
            }
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
