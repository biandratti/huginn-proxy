//! TCP SYN signal: capture client SYN packets for OS fingerprinting (p0f-style).

mod handler;
mod maps;
mod quirk_bits;
mod syn_raw;

pub use handler::handle_tcp_syn_v4;
pub use maps::{dst_ip, dst_port};
