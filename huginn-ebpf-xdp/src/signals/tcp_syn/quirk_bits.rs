use huginn_ebpf_common::quirk_bits;
use crate::constants::{IP_DF, IP_RF, IP_TOS_CE, IP_TOS_ECT};
use crate::headers::{IpHdr, TcpHdr};

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
