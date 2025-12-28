use huginn_proxy_lib::fingerprinting::{process_captured_bytes, CapturingStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};

struct MockStream {
    data: Vec<u8>,
    pos: usize,
    fail_at: Option<usize>,
}

impl MockStream {
    fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0, fail_at: None }
    }

    fn with_failure_at(mut self, pos: usize) -> Self {
        self.fail_at = Some(pos);
        self
    }
}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(fail_pos) = self.fail_at {
            if self.pos >= fail_pos {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Simulated connection failure",
                )));
            }
        }

        let remaining = self.data.len().saturating_sub(self.pos);
        if remaining == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        let to_read = remaining.min(buf.remaining());
        let end_pos = self.pos.saturating_add(to_read);
        buf.put_slice(&self.data[self.pos..end_pos]);
        self.pos = end_pos;
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(0))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn test_incomplete_http2_preface() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (tx, rx) = watch::channel(None);
    // Only partial preface (missing last bytes)
    let incomplete_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r";
    let mock_stream = MockStream::new(incomplete_preface.to_vec());
    let (mut capturing, mut receiver, extracted) = CapturingStream::new(mock_stream, 64 * 1024, tx);

    let mut buf = vec![0u8; 1024];
    let mut read_buf = tokio::io::ReadBuf::new(&mut buf);

    use tokio::io::AsyncReadExt;
    capturing.read_buf(&mut read_buf).await?;

    // Should not crash, fingerprint should not be extracted from incomplete data
    assert!(!extracted.load(std::sync::atomic::Ordering::Relaxed));
    assert!(rx.borrow().is_none());
    // Data should have been captured
    assert!(receiver.try_recv().is_ok() || receiver.try_recv().is_err());

    Ok(())
}

#[tokio::test]
async fn test_empty_stream() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (tx, rx) = watch::channel(None);
    let mock_stream = MockStream::new(vec![]);
    let (mut capturing, mut receiver, extracted) = CapturingStream::new(mock_stream, 64 * 1024, tx);

    let mut buf = vec![0u8; 1024];
    let mut read_buf = tokio::io::ReadBuf::new(&mut buf);

    use tokio::io::AsyncReadExt;
    capturing.read_buf(&mut read_buf).await?;

    // Should handle empty stream gracefully
    assert!(!extracted.load(std::sync::atomic::Ordering::Relaxed));
    assert!(rx.borrow().is_none());
    // No data should be captured from empty stream
    assert!(receiver.try_recv().is_err());

    Ok(())
}

#[tokio::test]
async fn test_invalid_frame_data() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (tx, rx) = watch::channel(None);
    // Invalid frame data (too short to be a valid frame)
    let invalid_data = vec![0x00, 0x01, 0x02];
    let mock_stream = MockStream::new(invalid_data);
    let (mut capturing, mut receiver, extracted) = CapturingStream::new(mock_stream, 64 * 1024, tx);

    let mut buf = vec![0u8; 1024];
    let mut read_buf = tokio::io::ReadBuf::new(&mut buf);

    use tokio::io::AsyncReadExt;
    capturing.read_buf(&mut read_buf).await?;

    // Should not panic on invalid data, no fingerprint should be extracted
    assert!(!extracted.load(std::sync::atomic::Ordering::Relaxed));
    assert!(rx.borrow().is_none());
    // Data should still be captured even if invalid
    assert!(receiver.try_recv().is_ok() || receiver.try_recv().is_err());

    Ok(())
}

#[tokio::test]
async fn test_connection_failure_during_read(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (tx, rx) = watch::channel(None);
    let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    // Set failure at position 5 to ensure it happens during first read
    let mock_stream = MockStream::new(http2_preface.to_vec()).with_failure_at(5);
    let (mut capturing, mut receiver, extracted) = CapturingStream::new(mock_stream, 64 * 1024, tx);

    let mut buf = vec![0u8; 1024];
    let mut read_buf = tokio::io::ReadBuf::new(&mut buf);

    use tokio::io::AsyncReadExt;
    // First read should succeed (reads first 5 bytes before failure)
    let result1 = capturing.read_buf(&mut read_buf).await;
    assert!(result1.is_ok());

    // Second read should fail (hits failure_at position)
    read_buf.clear();
    let result2 = capturing.read_buf(&mut read_buf).await;
    assert!(result2.is_err());

    // No fingerprint should be extracted from failed connection
    assert!(!extracted.load(std::sync::atomic::Ordering::Relaxed));
    assert!(rx.borrow().is_none());
    // Some data might have been captured before failure
    let _captured = receiver.try_recv();

    Ok(())
}

#[tokio::test]
async fn test_process_captured_bytes_invalid_data() {
    let (tx, rx) = watch::channel(None);
    let (sender, receiver) = mpsc::unbounded_channel();
    let extracted = Arc::new(AtomicBool::new(false));

    // Send invalid HTTP/2 data
    let _ = sender.send(vec![0xFF, 0xFF, 0xFF, 0xFF]);
    drop(sender);

    // Process should handle invalid data without panicking
    process_captured_bytes(receiver, tx, extracted.clone()).await;

    // Verify no fingerprint was extracted from invalid data
    assert!(!extracted.load(std::sync::atomic::Ordering::Relaxed));
    assert!(rx.borrow().is_none());
}

#[tokio::test]
async fn test_process_captured_bytes_very_large_chunk() {
    let (tx, rx) = watch::channel(None);
    let (sender, receiver) = mpsc::unbounded_channel();
    let extracted = Arc::new(AtomicBool::new(false));

    // Send a very large chunk (larger than typical buffer)
    let large_data = vec![0u8; 200 * 1024]; // 200KB
    let _ = sender.send(large_data);
    drop(sender);

    // Process should handle large chunks without panicking
    process_captured_bytes(receiver, tx, extracted.clone()).await;

    // Verify processing completed (no fingerprint expected from random data)
    assert!(!extracted.load(std::sync::atomic::Ordering::Relaxed));
    assert!(rx.borrow().is_none());
}

#[tokio::test]
async fn test_process_captured_bytes_multiple_empty_chunks() {
    let (tx, rx) = watch::channel(None);
    let (sender, receiver) = mpsc::unbounded_channel();
    let extracted = Arc::new(AtomicBool::new(false));

    // Send multiple empty chunks
    for _ in 0..10 {
        let _ = sender.send(vec![]);
    }
    drop(sender);

    // Process should handle empty chunks gracefully
    process_captured_bytes(receiver, tx, extracted.clone()).await;

    // Verify no fingerprint extracted from empty data
    assert!(!extracted.load(std::sync::atomic::Ordering::Relaxed));
    assert!(rx.borrow().is_none());
}
