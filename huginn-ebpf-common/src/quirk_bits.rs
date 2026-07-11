//! Quirk bitmask constants and computation for TCP SYN fingerprinting (p0f-style).

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
pub const NS: u32 = 1 << 10; // ECN Nonce Sum (RFC 3540)

use crate::constants::{IP_DF, IP_RF, IP_TOS_CE, IP_TOS_ECT};
use crate::headers::{Ip4Hdr, Ip6Hdr, TcpHdr};

/// Builds the quirk bitmask from IPv4 and TCP headers (SYN only).
///
/// Pure function: no packet or map access. Safe to call on host with mock headers.
#[inline(always)]
pub fn compute_v4(ip: &Ip4Hdr, tcp: &TcpHdr) -> u32 {
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
    if tcp.ece() || tcp.cwr() || (ip.tos & (IP_TOS_CE | IP_TOS_ECT) != 0) {
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
    if tcp.ns() {
        quirks |= NS;
    }
    quirks
}

/// Builds the quirk bitmask from IPv6 and TCP headers (SYN only).
///
/// IPv6-specific: `DF`, `NONZERO_ID`, `ZERO_ID`, `MUST_BE_ZERO` are never set
/// (they depend on IPv4 `id`/`frag_off` fields absent in IPv6). `ECN` is derived
/// from the traffic class byte and TCP ECE/CWR. All TCP-level quirks are identical
/// to the IPv4 path.
///
/// Pure function: no packet or map access. Safe to call on host with mock headers.
#[inline(always)]
pub fn compute_v6(ip6: &Ip6Hdr, tcp: &TcpHdr) -> u32 {
    let mut quirks: u32 = 0;
    let tc = ip6.traffic_class();

    if tcp.ece() || tcp.cwr() || (tc & (IP_TOS_CE | IP_TOS_ECT) != 0) {
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
    if tcp.ns() {
        quirks |= NS;
    }
    quirks
}
