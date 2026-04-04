use huginn_ebpf_common::quirk_bits;
use crate::constants::{IP_DF, IP_RF, IP_TOS_CE, IP_TOS_ECT};
use crate::headers::{Ip4Hdr, Ip6Hdr, TcpHdr};

/// Builds the quirk bitmask from IPv4 and TCP headers (SYN only).
///
/// Pure function: no packet or map access. Safe to test on host with mock headers.
#[inline(always)]
pub fn compute_quirks_v4(ip: &Ip4Hdr, tcp: &TcpHdr) -> u32 {
    let mut quirks: u32 = 0;
    let frag_off = ip.frag_off;
    let ip_id = ip.id;
    let df = frag_off & IP_DF != 0;

    if df {
        quirks |= quirk_bits::DF;
    }
    if df && ip_id != 0 {
        quirks |= quirk_bits::NONZERO_ID;
    }
    if !df && ip_id == 0 {
        quirks |= quirk_bits::ZERO_ID;
    }
    if frag_off & IP_RF != 0 {
        quirks |= quirk_bits::MUST_BE_ZERO;
    }
    if tcp.ece() || tcp.cwr() || (ip.tos & (IP_TOS_CE | IP_TOS_ECT) != 0) {
        quirks |= quirk_bits::ECN;
    }
    if tcp.seq == 0 {
        quirks |= quirk_bits::SEQ_ZERO;
    }
    if tcp.ack_seq != 0 {
        quirks |= quirk_bits::ACK_NONZERO;
    }
    if tcp.urg_ptr != 0 {
        quirks |= quirk_bits::NONZERO_URG;
    }
    if tcp.urg() {
        quirks |= quirk_bits::URG;
    }
    if tcp.psh() {
        quirks |= quirk_bits::PUSH;
    }
    if tcp.ns() {
        quirks |= quirk_bits::NS;
    }
    quirks
}

/// Builds the quirk bitmask from IPv6 and TCP headers (SYN only).
///
/// IPv6-specific notes:
/// - `DF`, `NonZeroID`, `ZeroID`, `MustBeZero` are not set: they depend on IPv4 fields
///   (id, frag_off) that do not exist in the IPv6 fixed header.
/// - `ECN` is derived from the traffic class byte (bits 0-1 = ECN CE/ECT) and TCP ECE/CWR.
/// - All TCP-level quirks are identical to the IPv4 path.
///
/// Pure function: no packet or map access. Safe to test on host with mock headers.
#[inline(always)]
pub fn compute_quirks_v6(ip6: &Ip6Hdr, tcp: &TcpHdr) -> u32 {
    let mut quirks: u32 = 0;
    let tc = ip6.traffic_class();

    if tcp.ece() || tcp.cwr() || (tc & (IP_TOS_CE | IP_TOS_ECT) != 0) {
        quirks |= quirk_bits::ECN;
    }
    if tcp.seq == 0 {
        quirks |= quirk_bits::SEQ_ZERO;
    }
    if tcp.ack_seq != 0 {
        quirks |= quirk_bits::ACK_NONZERO;
    }
    if tcp.urg_ptr != 0 {
        quirks |= quirk_bits::NONZERO_URG;
    }
    if tcp.urg() {
        quirks |= quirk_bits::URG;
    }
    if tcp.psh() {
        quirks |= quirk_bits::PUSH;
    }
    if tcp.ns() {
        quirks |= quirk_bits::NS;
    }
    quirks
}
