//! BPF program for TCP SYN fingerprinting.
//!
//! Captures TCP SYN packets and stores raw handshake data in a BPF LRU hash map
//! keyed by (src_ip, src_port). Direct Rust port of the former `bpf/xdp.c`.
//!
//! Two capture hooks share the same maps and capture logic in this single ELF:
//!   - `huginn_xdp_syn` (XDP): driver/generic hook, used on physical/veth interfaces.
//!   - `huginn_tc_syn` (TC clsact ingress): used on VLAN/bond interfaces where generic XDP drops
//!     GRO-merged data packets. See `data/ebpf-vlan-tc-capture.md`.
//!
//! The loader (`huginn-ebpf/src/probe.rs`) picks which one to attach. The map layout and global
//! variable names (`dst_ip_v4`, `dst_ip_v6`, `dst_port`) are identical so the userspace contract
//! is unchanged.
#![no_std]
#![no_main]
#![deny(unsafe_code)]

use aya_ebpf::{
    bindings::{xdp_action::XDP_PASS, TC_ACT_OK},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

mod constants;
mod handlers;
mod headers;
mod helpers;
mod signals;
mod tc;

// ── Entry points ─────────────────────────────────────────────────────────────

#[xdp]
pub fn huginn_xdp_syn(ctx: XdpContext) -> u32 {
    match handlers::try_xdp_syn(&ctx) {
        Ok(()) => XDP_PASS,
        Err(()) => XDP_PASS,
    }
}

/// TC clsact ingress classifier. Passive, read-only capture: always returns `TC_ACT_OK`
/// (the analogue of `XDP_PASS`), never `TC_ACT_SHOT`, so the datapath is never disturbed.
#[classifier]
pub fn huginn_tc_syn(ctx: TcContext) -> i32 {
    let _ = tc::try_tc_syn(&ctx);
    TC_ACT_OK
}

// ── Required for no_std + no_main ────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
