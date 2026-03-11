//! HTTP server that routes GET /metrics and GET /ready to the appropriate handlers.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use huginn_ebpf::pin;
use prometheus::Registry;
use tracing::info;

use crate::metrics;

pub fn spawn_server(registry: Arc<Registry>, pin_path: String, listen_addr: &str, port: u16) {
    let listen_addr = listen_addr.to_string();
    thread::spawn(move || {
        let listener = match TcpListener::bind((listen_addr.as_str(), port)) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%e, "server: bind failed");
                return;
            }
        };
        let addr = listener.local_addr().unwrap_or_else(|e| {
            tracing::error!(%e, "server: local_addr failed");
            std::process::exit(1);
        });
        info!(%addr, "metrics and health server listening");
        for stream in listener.incoming().flatten() {
            let registry = Arc::clone(&registry);
            let pin_path = pin_path.clone();
            thread::spawn(move || handle(stream, &registry, &pin_path));
        }
    });
}

fn handle(mut stream: std::net::TcpStream, registry: &Registry, pin_path: &str) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
    let mut reader = BufReader::new(&stream);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).is_err() {
        return;
    }
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    let (status, body): (_, String) = match path {
        "/metrics" => match metrics::encode_metrics(registry) {
            Ok(s) => ("200 OK", s),
            Err(e) => {
                tracing::warn!(%e, "metrics encode failed");
                ("500 Internal Server Error", format!("Error: {e}\n"))
            }
        },
        "/ready" => ready_response(pin_path),
        _ => ("404 Not Found", "Not Found\r\n".to_string()),
    };
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{}",
        status, body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn ready_response(pin_path: &str) -> (&'static str, String) {
    if pins_exist(pin_path) {
        ("200 OK", "ok\n".to_string())
    } else {
        ("503 Service Unavailable", "pins not ready\n".to_string())
    }
}

pub fn pins_exist(base: &str) -> bool {
    let base = Path::new(base);
    base.join(pin::SYN_MAP_V4_NAME).exists()
        && base.join(pin::COUNTER_NAME).exists()
        && base.join(pin::SYN_INSERT_FAILURES_NAME).exists()
}
