use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
use huginn_net_http::http2_parser::Http2Parser;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch};
use tracing::debug;

/// CapturingStream captures all data read from the inner stream
/// while passing it through, similar to how fingerproxy captures HTTP/2 frames
/// Processes fingerprint inline when possible to avoid race conditions
pub struct CapturingStream<S> {
    inner: S,
    sender: mpsc::UnboundedSender<Vec<u8>>, // Lock-free channel
    fingerprint_tx: watch::Sender<Option<String>>, // Direct access to update fingerprint
    fingerprint_extracted: Arc<AtomicBool>,
    max_capture: usize,
    captured_len: Arc<AtomicUsize>,
    buffer: Vec<u8>,              // Inline buffer for fast processing
    parser: Http2Parser<'static>, // Reused parser for efficiency
    parsed_offset: usize,
}

impl<S> CapturingStream<S> {
    pub fn new(
        inner: S,
        max_capture: usize,
        fingerprint_tx: watch::Sender<Option<String>>,
    ) -> (Self, mpsc::UnboundedReceiver<Vec<u8>>, Arc<AtomicBool>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let fingerprint_extracted = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                sender,
                fingerprint_tx,
                fingerprint_extracted: fingerprint_extracted.clone(),
                max_capture,
                captured_len: Arc::new(AtomicUsize::new(0)),
                buffer: Vec::with_capacity(64 * 1024),
                parser: Http2Parser::new(),
                parsed_offset: 0,
            },
            receiver,
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

        // Capture bytes and process fingerprint inline when possible (NO WAITS!)
        // Process fingerprint immediately to avoid race conditions
        if after > before && !self.fingerprint_extracted.load(Ordering::Relaxed) {
            let read_data = &buf.filled()[before..after];
            let current_len = self.captured_len.load(Ordering::Relaxed);

            if current_len < self.max_capture {
                let remaining = self.max_capture.saturating_sub(current_len);
                let to_capture = read_data.len().min(remaining);
                let data_to_process = &read_data[..to_capture];

                // Send via lock-free channel for background processing
                if self.sender.send(data_to_process.to_vec()).is_ok() {
                    self.captured_len
                        .store(current_len.saturating_add(to_capture), Ordering::Relaxed);
                }

                // Process fingerprint INLINE immediately (no waits, no race conditions!)
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
                                    // Update fingerprint immediately (no waits, no race conditions!)
                                    let _ = self.fingerprint_tx.send(Some(fingerprint.fingerprint));
                                    self.fingerprint_extracted.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(_) => {
                            // Parsing error, continue (might need more data)
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
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Process captured bytes in a separate task (lock-free)
/// Similar to how fingerproxy processes frames without locks
pub async fn process_captured_bytes(
    mut receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    fingerprint_tx: watch::Sender<Option<String>>, // Watch channel for multiple readers
    fingerprint_extracted: Arc<AtomicBool>,
) {
    let mut buffer = Vec::with_capacity(64 * 1024);
    let parser = Http2Parser::new();
    let mut parsed_offset = 0;

    while let Some(chunk) = receiver.recv().await {
        if fingerprint_extracted.load(Ordering::Relaxed) {
            break;
        }

        buffer.extend_from_slice(&chunk);
        debug!(
            "process_captured_bytes: received {} bytes (total: {})",
            chunk.len(),
            buffer.len()
        );

        // Use parse_frames_skip_preface to handle preface automatically
        let frame_data = if parsed_offset == 0 {
            &buffer[..]
        } else {
            &buffer[parsed_offset..]
        };

        if frame_data.len() >= 9 {
            match parser.parse_frames_skip_preface(frame_data) {
                Ok((frames, bytes_consumed)) => {
                    if !frames.is_empty() {
                        debug!("process_captured_bytes: parsed {} frames", frames.len());
                        // Update parsed_offset based on actual bytes consumed (includes preface if present)
                        parsed_offset = parsed_offset.saturating_add(bytes_consumed);

                        if let Some(fingerprint) = extract_akamai_fingerprint(&frames) {
                            debug!(
                                "process_captured_bytes: extracted fingerprint: {}",
                                fingerprint.fingerprint
                            );
                            // Send via watch channel (allows multiple readers, always has latest value)
                            let _ = fingerprint_tx.send(Some(fingerprint.fingerprint));
                            fingerprint_extracted.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("process_captured_bytes: parsing error: {:?}", e);
                    // Continue, might need more data
                }
            }
        }
    }
}

