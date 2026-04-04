//! TCP SYN signal: capture client SYN packets for OS fingerprinting (p0f-style).
//!
//! Contract with `huginn-ebpf`: map names (`tcp_syn_map_v4`, `tcp_syn_map_v6`,
//! `syn_counter`, `syn_insert_failures`, `syn_captured`, `syn_malformed` and their
//! `_v6` counterparts), layout of `SynRawDataV4`/`SynRawDataV6`, and key encoding via
//! `make_key` / `make_key_v6` / `make_bpf_key` / `make_bpf_key_v6` must stay in sync.

mod handler;
mod maps;
mod quirk_bits;

pub use handler::{handle_tcp_syn_v4, handle_tcp_syn_v6};
pub use maps::{dst_ip, dst_ip_v6, dst_port, increment_syn_malformed_v4, increment_syn_malformed_v6};
