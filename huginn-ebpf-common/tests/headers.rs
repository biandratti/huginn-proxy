//! Tests for the `TcpHdr`, `Ip4Hdr`, and `Ip6Hdr` bit-field accessors.
//!
//! These guard the `__LITTLE_ENDIAN_BITFIELD` bit math. `offset_flags` is a LE u16
//! where the low byte holds `res1` (bits 0-3) and `doff` (bits 4-7), and the high
//! byte holds the TCP flags. All values below are hand-computed against that layout.

use huginn_ebpf_common::headers::{Ip4Hdr, Ip6Hdr, TcpHdr};

// ── Helper constructors ───────────────────────────────────────────────────────

fn tcp_hdr(offset_flags: u16) -> TcpHdr {
    TcpHdr {
        source: 0,
        dest: 0,
        seq: 0,
        ack_seq: 0,
        offset_flags,
        window: 0,
        check: 0,
        urg_ptr: 0,
    }
}

fn ip4_hdr(version_ihl: u8) -> Ip4Hdr {
    Ip4Hdr {
        version_ihl,
        tos: 0,
        tot_len: 0,
        id: 0,
        frag_off: 0,
        ttl: 64,
        protocol: 6,
        check: 0,
        saddr: 0,
        daddr: 0,
    }
}

fn ip6_hdr(priority_version: u8, flow_lbl_0: u8) -> Ip6Hdr {
    Ip6Hdr {
        priority_version,
        flow_lbl: [flow_lbl_0, 0, 0],
        payload_len: 0,
        nexthdr: 6,
        hop_limit: 64,
        saddr: [0u8; 16],
        daddr: [0u8; 16],
    }
}

// ── TcpHdr::doff ─────────────────────────────────────────────────────────────

#[test]
fn tcp_doff_typical_values() {
    // doff=5 (20 bytes) → bits [4-7] of low byte = 0x50
    assert_eq!(tcp_hdr(0x0050).doff(), 5);
    // doff=8 (32 bytes) → 0x80
    assert_eq!(tcp_hdr(0x0080).doff(), 8);
    // doff=15 (max, 60 bytes) → 0xF0
    assert_eq!(tcp_hdr(0x00F0).doff(), 15);
    // doff=0
    assert_eq!(tcp_hdr(0x0000).doff(), 0);
}

// ── TcpHdr flag bits ──────────────────────────────────────────────────────────

#[test]
fn tcp_syn_flag() {
    // SYN = bit 9 of offset_flags (second bit of high byte = 0x0200)
    assert!(tcp_hdr(0x0200).syn());
    assert!(!tcp_hdr(0x0000).syn());
    assert!(!tcp_hdr(0x0100).syn()); // FIN only
}

#[test]
fn tcp_ack_flag() {
    // ACK = bit 12 = 0x1000
    assert!(tcp_hdr(0x1000).ack());
    assert!(!tcp_hdr(0x0000).ack());
}

#[test]
fn tcp_syn_ack_combined() {
    // SYN+ACK = 0x1200
    let h = tcp_hdr(0x1200);
    assert!(h.syn());
    assert!(h.ack());
}

#[test]
fn tcp_psh_flag() {
    // PSH = bit 11 = 0x0800
    assert!(tcp_hdr(0x0800).psh());
    assert!(!tcp_hdr(0x0000).psh());
}

#[test]
fn tcp_urg_flag() {
    // URG = bit 13 = 0x2000
    assert!(tcp_hdr(0x2000).urg());
    assert!(!tcp_hdr(0x0000).urg());
}

#[test]
fn tcp_ece_flag() {
    // ECE = bit 14 = 0x4000
    assert!(tcp_hdr(0x4000).ece());
    assert!(!tcp_hdr(0x0000).ece());
}

#[test]
fn tcp_cwr_flag() {
    // CWR = bit 15 = 0x8000
    assert!(tcp_hdr(0x8000).cwr());
    assert!(!tcp_hdr(0x0000).cwr());
}

#[test]
fn tcp_ns_flag() {
    // NS = bit 3 of low byte = 0x0008
    assert!(tcp_hdr(0x0008).ns());
    assert!(!tcp_hdr(0x0000).ns());
}

#[test]
fn tcp_flags_are_independent() {
    // Every flag the accessors expose, set simultaneously.
    let all: u16 = 0xFF00 | 0x0008; // all high-byte flag bits + NS (bit 3)
    let h = tcp_hdr(all);
    assert!(h.syn() && h.ack() && h.psh() && h.urg() && h.ece() && h.cwr() && h.ns());
}

// ── Ip4Hdr::ihl ──────────────────────────────────────────────────────────────

#[test]
fn ip4_ihl_typical() {
    // version=4 (0x40) | ihl=5 (0x05) = 0x45
    assert_eq!(ip4_hdr(0x45).ihl(), 5);
    // ihl=6 (24 bytes, has options): 0x46
    assert_eq!(ip4_hdr(0x46).ihl(), 6);
    // ihl=15 (max): 0x4F
    assert_eq!(ip4_hdr(0x4F).ihl(), 15);
}

// ── Ip6Hdr::traffic_class ────────────────────────────────────────────────────

#[test]
fn ip6_traffic_class_zero() {
    // version=6 (0x60), tc=0 → priority_version=0x60, flow_lbl[0]=0x00
    assert_eq!(ip6_hdr(0x60, 0x00).traffic_class(), 0x00);
}

#[test]
fn ip6_traffic_class_full() {
    // tc=0xFF: tc_high=0x0F in priority_version, tc_low=0xF0 in flow_lbl[0]
    // priority_version = 0x6F (version=6, tc_high=0xF)
    // flow_lbl[0] = 0xF0 (tc_low=0xF in high nibble)
    assert_eq!(ip6_hdr(0x6F, 0xF0).traffic_class(), 0xFF);
}

#[test]
fn ip6_traffic_class_dscp46_ecn0() {
    // DSCP 46 (EF) = 0b101110 → tc = 0xB8 (101110_00)
    // tc_high = 0x0B, tc_low = 0x80
    // priority_version = 0x6B, flow_lbl[0] = 0x80
    assert_eq!(ip6_hdr(0x6B, 0x80).traffic_class(), 0xB8);
}
