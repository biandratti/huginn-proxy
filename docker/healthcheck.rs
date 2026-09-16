//! Minimal shell-free HTTP health probe for distroless runtime images.

use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let address = args
        .next()
        .ok_or_else(|| "usage: healthcheck <IP:PORT> <PATH>".to_string())?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid socket address: {error}"))?;
    let path = args
        .next()
        .ok_or_else(|| "usage: healthcheck <IP:PORT> <PATH>".to_string())?;
    if args.next().is_some() || !path.starts_with('/') {
        return Err("usage: healthcheck <IP:PORT> <PATH>".to_string());
    }

    let timeout = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("connect failed: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("setting read timeout failed: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("setting write timeout failed: {error}"))?;

    let host = match address.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    write!(stream, "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
        .map_err(|error| format!("request failed: {error}"))?;

    let mut response = [0_u8; 12];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("response failed: {error}"))?;
    if response.starts_with(b"HTTP/1.1 200") || response.starts_with(b"HTTP/1.0 200") {
        Ok(())
    } else {
        Err(format!("unhealthy response: {}", String::from_utf8_lossy(&response)))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("healthcheck: {error}");
            ExitCode::FAILURE
        }
    }
}
