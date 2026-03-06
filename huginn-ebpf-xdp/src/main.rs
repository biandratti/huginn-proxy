//! XDP program for TCP SYN fingerprinting.
//!
//! Captures TCP SYN packets and stores raw handshake data in a BPF LRU hash map
//! keyed by (src_ip, src_port). Direct Rust port of the former `bpf/xdp.c`.
//!
//! The map layout and global variable names (`dst_ip`, `dst_port`) are identical
//! to the C version so `huginn-ebpf/src/probe.rs` requires no changes.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::xdp,
    programs::XdpContext,
};

mod constants;
mod headers;
mod helpers;
mod handlers;
mod signals;

// ── Entry point ──────────────────────────────────────────────────────────────

#[xdp]
pub fn huginn_xdp_syn(ctx: XdpContext) -> u32 {
    match handlers::try_xdp_syn(&ctx) {
        Ok(()) => aya_ebpf::bindings::xdp_action::XDP_PASS,
        Err(()) => aya_ebpf::bindings::xdp_action::XDP_PASS,
    }
}

// ── Required for no_std + no_main ────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
