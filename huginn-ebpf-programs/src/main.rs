//! TCP SYN capture: XDP and TC clsact hooks in one ELF.
#![no_std]
#![no_main]
#![deny(unsafe_code)]

use aya_ebpf::{
    bindings::{xdp_action::XDP_PASS, TC_ACT_OK},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

mod signals;
mod tc;
mod xdp;

// The capture pipelines never drop: an over-rate-limit SYN is simply not captured (skipped),
// and the packet always passes through to the stack.
#[xdp]
pub fn huginn_xdp_syn(ctx: XdpContext) -> u32 {
    xdp::try_xdp_syn(&ctx);
    XDP_PASS
}

#[classifier]
pub fn huginn_tc_syn(ctx: TcContext) -> i32 {
    tc::try_tc_syn(&ctx);
    TC_ACT_OK
}

// Entry-point names must match huginn_ebpf_common::constants::{XDP_SYN_PROGRAM, TC_SYN_PROGRAM}.
const _: () = assert!(huginn_ebpf_common::str_eq(
    stringify!(huginn_xdp_syn),
    huginn_ebpf_common::constants::XDP_SYN_PROGRAM,
));
const _: () = assert!(huginn_ebpf_common::str_eq(
    stringify!(huginn_tc_syn),
    huginn_ebpf_common::constants::TC_SYN_PROGRAM,
));

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
