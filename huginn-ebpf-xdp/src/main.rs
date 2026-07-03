//! XDP program for TCP SYN fingerprinting.
//!
//! Captures TCP SYN packets and stores raw handshake data in a BPF LRU hash map
//! keyed by (src_ip, src_port). Direct Rust port of the former `bpf/xdp.c`.
//!
//! The map layout and global variable names (`dst_ip_v4`, `dst_ip_v6`, `dst_port`) match the
//! names patched by `huginn-ebpf/src/probe.rs` at load time.
#![no_std]
#![no_main]
#![deny(unsafe_code)]

use aya_ebpf::{bindings::xdp_action::XDP_PASS, macros::xdp, programs::XdpContext};

mod constants;
mod handlers;
mod headers;
mod helpers;
mod signals;

// ── Entry point ──────────────────────────────────────────────────────────────

#[xdp]
pub fn huginn_xdp_syn(ctx: XdpContext) -> u32 {
    match handlers::try_xdp_syn(&ctx) {
        Ok(()) => XDP_PASS,
        Err(()) => XDP_PASS,
    }
}

// ── Required for no_std + no_main ────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
