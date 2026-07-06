//! Tests for `quirk_bits::compute_v4` and `quirk_bits::compute_v6`.
//!
//! Each test constructs minimal `Ip4Hdr`/`Ip6Hdr`/`TcpHdr` values and asserts
//! that the expected quirk bits are set (or absent).

use huginn_ebpf_common::{
    constants::{IP_DF, IP_MF, IP_RF, IP_TOS_CE, IP_TOS_ECT},
    headers::{Ip4Hdr, Ip6Hdr, TcpHdr},
    quirk_bits::{self, compute_v4, compute_v6},
};

// ── Builder helpers ───────────────────────────────────────────────────────────

/// Baseline IPv4 header: DF set, non-zero ID, no ECN, standard TTL.
fn ip4(frag_off: u16, id: u16, tos: u8) -> Ip4Hdr {
    Ip4Hdr {
        version_ihl: 0x45,
        tos,
        tot_len: 60,
        id,
        frag_off,
        ttl: 64,
        protocol: 6,
        check: 0,
        saddr: 0x0100_007F, // 127.0.0.1 NBO
        daddr: 0x0200_007F,
    }
}

/// Baseline IPv6 header. `priority_version` encodes version=6 + tc_high.
fn ip6(priority_version: u8, flow_lbl_0: u8) -> Ip6Hdr {
    Ip6Hdr {
        priority_version,
        flow_lbl: [flow_lbl_0, 0, 0],
        payload_len: 40,
        nexthdr: 6,
        hop_limit: 64,
        saddr: [0u8; 16],
        daddr: [0u8; 16],
    }
}

/// TCP header with all flags clear and the given `seq`, `ack_seq`, `urg_ptr`.
fn tcp(offset_flags: u16, seq: u32, ack_seq: u32, urg_ptr: u16) -> TcpHdr {
    TcpHdr {
        source: 12345_u16.to_be(),
        dest: 443_u16.to_be(),
        seq,
        ack_seq,
        offset_flags,
        window: 65535,
        check: 0,
        urg_ptr,
    }
}

/// SYN-only TCP header (doff=10, SYN bit set, no ACK).
fn syn_tcp() -> TcpHdr {
    // doff=10 (0xA0 in low byte), SYN=bit9 (0x0200)
    tcp(0x0200 | 0x00A0, 0xDEAD_BEEF, 0, 0)
}

// ── compute_v4: DF / ID quirks ────────────────────────────────────────────────

#[test]
fn v4_df_set() {
    let q = compute_v4(&ip4(IP_DF, 1234, 0), &syn_tcp());
    assert_ne!(q & quirk_bits::DF, 0);
}

#[test]
fn v4_df_clear() {
    let q = compute_v4(&ip4(0, 1234, 0), &syn_tcp());
    assert_eq!(q & quirk_bits::DF, 0);
}

#[test]
fn v4_nonzero_id_when_df_set_and_id_nonzero() {
    let q = compute_v4(&ip4(IP_DF, 0x1234, 0), &syn_tcp());
    assert_ne!(q & quirk_bits::NONZERO_ID, 0);
    assert_eq!(q & quirk_bits::ZERO_ID, 0);
}

#[test]
fn v4_no_nonzero_id_when_df_set_and_id_zero() {
    let q = compute_v4(&ip4(IP_DF, 0, 0), &syn_tcp());
    assert_eq!(q & quirk_bits::NONZERO_ID, 0);
}

#[test]
fn v4_zero_id_when_df_clear_and_id_zero() {
    let q = compute_v4(&ip4(0, 0, 0), &syn_tcp());
    assert_ne!(q & quirk_bits::ZERO_ID, 0);
    assert_eq!(q & quirk_bits::NONZERO_ID, 0);
}

#[test]
fn v4_no_zero_id_when_df_clear_and_id_nonzero() {
    let q = compute_v4(&ip4(IP_MF, 0x1, 0), &syn_tcp());
    assert_eq!(q & quirk_bits::ZERO_ID, 0);
}

#[test]
fn v4_must_be_zero_when_rf_set() {
    let q = compute_v4(&ip4(IP_RF, 0, 0), &syn_tcp());
    assert!(q & quirk_bits::MUST_BE_ZERO != 0);
}

#[test]
fn v4_must_be_zero_absent_when_rf_clear() {
    let q = compute_v4(&ip4(IP_DF, 1, 0), &syn_tcp());
    assert_eq!(q & quirk_bits::MUST_BE_ZERO, 0);
}

// ── compute_v4: ECN ───────────────────────────────────────────────────────────

#[test]
fn v4_ecn_via_tcp_ece() {
    let t = tcp(0x0200 | 0x00A0 | 0x4000, 0, 0, 0); // ECE bit = 0x4000
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_ne!(q & quirk_bits::ECN, 0);
}

#[test]
fn v4_ecn_via_tcp_cwr() {
    let t = tcp(0x0200 | 0x00A0 | 0x8000, 0, 0, 0); // CWR bit = 0x8000
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_ne!(q & quirk_bits::ECN, 0);
}

#[test]
fn v4_ecn_via_ip_tos_ce() {
    let q = compute_v4(&ip4(IP_DF, 1, IP_TOS_CE), &syn_tcp());
    assert_ne!(q & quirk_bits::ECN, 0);
}

#[test]
fn v4_ecn_via_ip_tos_ect() {
    let q = compute_v4(&ip4(IP_DF, 1, IP_TOS_ECT), &syn_tcp());
    assert_ne!(q & quirk_bits::ECN, 0);
}

#[test]
fn v4_no_ecn_when_clean() {
    let q = compute_v4(&ip4(IP_DF, 1, 0), &syn_tcp());
    assert_eq!(q & quirk_bits::ECN, 0);
}

// ── compute_v4: TCP-level quirks ──────────────────────────────────────────────

#[test]
fn v4_seq_zero() {
    let t = tcp(0x0200 | 0x00A0, 0, 0, 0);
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_ne!(q & quirk_bits::SEQ_ZERO, 0);
}

#[test]
fn v4_seq_nonzero() {
    let t = tcp(0x0200 | 0x00A0, 1, 0, 0);
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_eq!(q & quirk_bits::SEQ_ZERO, 0);
}

#[test]
fn v4_ack_nonzero() {
    let t = tcp(0x0200 | 0x00A0, 0, 1, 0);
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_ne!(q & quirk_bits::ACK_NONZERO, 0);
}

#[test]
fn v4_urg_ptr_nonzero() {
    let t = tcp(0x0200 | 0x00A0, 0, 0, 1);
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_ne!(q & quirk_bits::NONZERO_URG, 0);
}

#[test]
fn v4_urg_flag() {
    // URG flag = bit 13 = 0x2000
    let t = tcp(0x0200 | 0x00A0 | 0x2000, 0, 0, 0);
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_ne!(q & quirk_bits::URG, 0);
}

#[test]
fn v4_push_flag() {
    // PSH flag = bit 11 = 0x0800
    let t = tcp(0x0200 | 0x00A0 | 0x0800, 0, 0, 0);
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_ne!(q & quirk_bits::PUSH, 0);
}

#[test]
fn v4_ns_flag() {
    // NS = bit 3 of low byte = 0x0008
    let t = tcp(0x0200 | 0x00A0 | 0x0008, 0, 0, 0);
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    assert_ne!(q & quirk_bits::NS, 0);
}

#[test]
fn v4_clean_syn_has_no_quirks() {
    // DF set, non-zero ID, seq != 0, no flags beyond SYN
    let t = tcp(0x0200 | 0x00A0, 1, 0, 0);
    let q = compute_v4(&ip4(IP_DF, 1, 0), &t);
    // Only DF and NONZERO_ID expected
    assert_eq!(q & !(quirk_bits::DF | quirk_bits::NONZERO_ID), 0);
}

// ── compute_v6: IPv4-only quirks must not appear ──────────────────────────────

#[test]
fn v6_never_sets_ipv4_quirks() {
    let ipv4_only =
        quirk_bits::DF | quirk_bits::NONZERO_ID | quirk_bits::ZERO_ID | quirk_bits::MUST_BE_ZERO;
    // Worst-case traffic class (all ECN bits set)
    let q = compute_v6(&ip6(0x6F, 0xF3), &syn_tcp());
    assert_eq!(q & ipv4_only, 0, "IPv4-only quirks must never appear in v6: {q:#010x}");
}

// ── compute_v6: ECN ───────────────────────────────────────────────────────────

#[test]
fn v6_ecn_via_tcp_ece() {
    let t = tcp(0x0200 | 0x00A0 | 0x4000, 0, 0, 0);
    let q = compute_v6(&ip6(0x60, 0x00), &t);
    assert_ne!(q & quirk_bits::ECN, 0);
}

#[test]
fn v6_ecn_via_traffic_class_ce() {
    // tc = 0x03 (CE|ECT bits); tc_high=0x00, tc_low in flow_lbl[0] high nibble = 0x30
    // priority_version = 0x60 (ver=6, tc_high=0), flow_lbl[0] = 0x30
    let q = compute_v6(&ip6(0x60, 0x30), &syn_tcp());
    assert_ne!(q & quirk_bits::ECN, 0);
}

#[test]
fn v6_no_ecn_when_clean() {
    let q = compute_v6(&ip6(0x60, 0x00), &syn_tcp());
    assert_eq!(q & quirk_bits::ECN, 0);
}

// ── compute_v6: TCP-level quirks (identical to v4 path) ──────────────────────

#[test]
fn v6_seq_zero() {
    let t = tcp(0x0200 | 0x00A0, 0, 0, 0);
    let q = compute_v6(&ip6(0x60, 0x00), &t);
    assert_ne!(q & quirk_bits::SEQ_ZERO, 0);
}

#[test]
fn v6_ack_nonzero() {
    let t = tcp(0x0200 | 0x00A0, 0, 1, 0);
    let q = compute_v6(&ip6(0x60, 0x00), &t);
    assert_ne!(q & quirk_bits::ACK_NONZERO, 0);
}

#[test]
fn v6_push_flag() {
    let t = tcp(0x0200 | 0x00A0 | 0x0800, 0, 0, 0);
    let q = compute_v6(&ip6(0x60, 0x00), &t);
    assert_ne!(q & quirk_bits::PUSH, 0);
}

#[test]
fn v6_clean_syn_has_no_quirks() {
    let t = tcp(0x0200 | 0x00A0, 1, 0, 0);
    let q = compute_v6(&ip6(0x60, 0x00), &t);
    assert_eq!(q, 0, "clean IPv6 SYN should produce no quirks, got {q:#010x}");
}
