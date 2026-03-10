//! Quirk bitmask for TCP SYN fingerprinting (p0f-style).
//!
//! Must match the identical module in `huginn-ebpf/src/types.rs`.

use crate::constants::{IP_DF, IP_RF};
use crate::headers::{IpHdr, TcpHdr};

/// Quirk bitmask constants extracted from IP and TCP headers (TCP SYN signal).
pub const DF: u32 = 1 << 0;
pub const NONZERO_ID: u32 = 1 << 1;
pub const ZERO_ID: u32 = 1 << 2;
pub const MUST_BE_ZERO: u32 = 1 << 3;
pub const ECN: u32 = 1 << 4;
pub const SEQ_ZERO: u32 = 1 << 5;
pub const ACK_NONZERO: u32 = 1 << 6;
pub const NONZERO_URG: u32 = 1 << 7;
pub const URG: u32 = 1 << 8;
pub const PUSH: u32 = 1 << 9;

/// Builds the quirk bitmask from IPv4 and TCP headers (SYN only).
///
/// Pure function: no packet or map access. Safe to test on host with mock headers.
#[inline(always)]
pub fn compute_quirks(ip: &IpHdr, tcp: &TcpHdr) -> u32 {
    let mut quirks: u32 = 0;
    let frag_off = ip.frag_off;
    let ip_id = ip.id;
    let df = frag_off & IP_DF != 0;

    if df {
        quirks |= DF;
    }
    if df && ip_id != 0 {
        quirks |= NONZERO_ID;
    }
    if !df && ip_id == 0 {
        quirks |= ZERO_ID;
    }
    if frag_off & IP_RF != 0 {
        quirks |= MUST_BE_ZERO;
    }
    if tcp.ece() || tcp.cwr() {
        quirks |= ECN;
    }
    if tcp.seq == 0 {
        quirks |= SEQ_ZERO;
    }
    if tcp.ack_seq != 0 {
        quirks |= ACK_NONZERO;
    }
    if tcp.urg_ptr != 0 {
        quirks |= NONZERO_URG;
    }
    if tcp.urg() {
        quirks |= URG;
    }
    if tcp.psh() {
        quirks |= PUSH;
    }
    quirks
}
