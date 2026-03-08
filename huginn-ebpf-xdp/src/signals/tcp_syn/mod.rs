//! TCP SYN signal: capture client SYN packets for OS fingerprinting (p0f-style).
//!
//! Contract with `huginn-ebpf`: map names (`tcp_syn_map_v4`, `syn_counter`, `syn_insert_failures`),
//! layout of `SynRawData`, and key encoding via `make_key` / `make_bpf_key` must stay in sync.

mod handler;
mod maps;
mod quirk_bits;
mod syn_raw;

pub use handler::handle_tcp_syn_v4;
pub use maps::{dst_ip, dst_port};
