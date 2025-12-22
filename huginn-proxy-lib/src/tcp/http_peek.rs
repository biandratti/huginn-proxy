#![forbid(unsafe_code)]

use std::cmp;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub enum PeekOutcome {
    Http(PeekedHttp),
    NotHttp(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct PeekedHttp {
    #[allow(dead_code)]
    pub method: String,
    pub path: String,
    #[allow(dead_code)]
    pub version: String,
    pub buffered: Vec<u8>,
}

/// Peek the incoming stream for an HTTP/1.1 request-line.
/// Returns the parsed request-line and the buffered bytes (to be replayed to upstream),
/// or the buffered bytes if it doesn't look like HTTP.
pub async fn peek_request_line(
    stream: &mut TcpStream,
    max_peek: usize,
) -> std::io::Result<PeekOutcome> {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.peek(&mut tmp).await?;
        if n == 0 {
            return Ok(PeekOutcome::NotHttp(buf));
        }
        let take = cmp::min(n, tmp.len());
        buf.extend_from_slice(&tmp[..take]);
        if buf.len() >= max_peek {
            return Ok(PeekOutcome::NotHttp(buf));
        }
        if let Some(pos) = find_double_crlf(&buf) {
            let header = &buf[..pos];
            if let Some((method, path, version)) = parse_request_line(header) {
                return Ok(PeekOutcome::Http(PeekedHttp { method, path, version, buffered: buf }));
            } else {
                return Ok(PeekOutcome::NotHttp(buf));
            }
        }
        // If not complete, read more
        let read_n = stream.read(&mut tmp).await?;
        if read_n == 0 {
            return Ok(PeekOutcome::NotHttp(buf));
        }
        buf.extend_from_slice(&tmp[..read_n]);
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|p| p.checked_add(4))
}

fn parse_request_line(buf: &[u8]) -> Option<(String, String, String)> {
    let mut lines = buf.split(|b| *b == b'\n');
    let line = lines.next()?.trim_ascii_end();
    let parts: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
    if parts.len() < 3 {
        return None;
    }
    let method = std::str::from_utf8(parts[0]).ok()?.to_string();
    let path = std::str::from_utf8(parts[1]).ok()?.to_string();
    let version = std::str::from_utf8(parts[2]).ok()?.to_string();
    Some((method, path, version))
}

/// Replay buffered bytes into the upstream connection before starting bidirectional copy.
pub async fn replay_buffered(upstream: &mut TcpStream, buffered: &[u8]) -> std::io::Result<()> {
    upstream.write_all(buffered).await
}
