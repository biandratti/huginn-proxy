//! Tests for the network constants in `huginn_ebpf_common::constants`.
//!
//! Guards the `.swap_bytes()` trick: values must equal the expected
//! network-byte-order representation as read by a little-endian CPU.

use huginn_ebpf_common::constants::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IPV4, ETH_P_IPV6, IPPROTO_TCP, IP_DF, IP_MF, IP_OFFSET, IP_RF,
    IP_TOS_CE, IP_TOS_ECT, TCPOPT_MAXLEN, TCP_SYN_MAP_V4_MAX_ENTRIES, TCP_SYN_MAP_V6_MAX_ENTRIES,
};

// ── EtherType ─────────────────────────────────────────────────────────────────

#[test]
fn ethertype_ipv4_is_network_order() {
    // 0x0800 in network order = [0x08, 0x00]; read as LE u16 = 0x0008
    assert_eq!(ETH_P_IPV4, 0x0800_u16.swap_bytes());
    assert_eq!(ETH_P_IPV4, 0x0008);
}

#[test]
fn ethertype_ipv6_is_network_order() {
    assert_eq!(ETH_P_IPV6, 0x86DD_u16.swap_bytes());
    assert_eq!(ETH_P_IPV6, 0xDD86);
}

#[test]
fn ethertype_8021q_is_network_order() {
    assert_eq!(ETH_P_8021Q, 0x8100_u16.swap_bytes());
    assert_eq!(ETH_P_8021Q, 0x0081);
}

#[test]
fn ethertype_8021ad_is_network_order() {
    assert_eq!(ETH_P_8021AD, 0x88A8_u16.swap_bytes());
    assert_eq!(ETH_P_8021AD, 0xA888);
}

// ── IPv4 fragment flags / offset ──────────────────────────────────────────────

#[test]
fn ip_rf_is_network_order() {
    // Reserved bit (bit 15 in host order) = 0x8000; NBO on LE = 0x0080
    assert_eq!(IP_RF, 0x8000_u16.swap_bytes());
    assert_eq!(IP_RF, 0x0080);
}

#[test]
fn ip_df_is_network_order() {
    // DF (bit 14 in host order) = 0x4000; NBO on LE = 0x0040
    assert_eq!(IP_DF, 0x4000_u16.swap_bytes());
    assert_eq!(IP_DF, 0x0040);
}

#[test]
fn ip_mf_is_network_order() {
    assert_eq!(IP_MF, 0x2000_u16.swap_bytes());
    assert_eq!(IP_MF, 0x0020);
}

#[test]
fn ip_offset_mask_is_network_order() {
    assert_eq!(IP_OFFSET, 0x1FFF_u16.swap_bytes());
    assert_eq!(IP_OFFSET, 0xFF1F);
}

#[test]
fn ip_flags_do_not_overlap() {
    assert_eq!(IP_RF & IP_DF, 0);
    assert_eq!(IP_RF & IP_MF, 0);
    assert_eq!(IP_DF & IP_MF, 0);
    // OFFSET covers none of the flag bits
    assert_eq!(IP_RF & IP_OFFSET, 0);
    assert_eq!(IP_DF & IP_OFFSET, 0);
    assert_eq!(IP_MF & IP_OFFSET, 0);
}

// ── ToS ECN bits ─────────────────────────────────────────────────────────────

#[test]
fn ip_tos_ecn_bits() {
    assert_eq!(IP_TOS_CE, 0x01);
    assert_eq!(IP_TOS_ECT, 0x02);
    assert_eq!(IP_TOS_CE & IP_TOS_ECT, 0);
}

// ── Misc ──────────────────────────────────────────────────────────────────────

#[test]
fn ipproto_tcp_value() {
    assert_eq!(IPPROTO_TCP, 6);
}

#[test]
fn tcpopt_maxlen_value() {
    // TCP header max is 60 bytes; fixed is 20; max options = 40.
    assert_eq!(TCPOPT_MAXLEN, 40);
}

#[test]
fn syn_map_default_capacities() {
    assert_eq!(TCP_SYN_MAP_V4_MAX_ENTRIES, 8192);
    assert_eq!(TCP_SYN_MAP_V6_MAX_ENTRIES, 8192);
}
