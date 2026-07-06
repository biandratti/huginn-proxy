// Constants now live in huginn-ebpf-common so they can be tested on host.
// Re-export the ones this crate uses so all call sites remain unchanged.
// (IP_DF/IP_RF/IP_TOS_* are consumed only by quirk computation, which now lives in common.)
pub use huginn_ebpf_common::constants::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IPV4, ETH_P_IPV6, IP_MF, IP_OFFSET, IPPROTO_TCP,
    TCPOPT_MAXLEN, TCP_SYN_MAP_V4_MAX_ENTRIES, TCP_SYN_MAP_V6_MAX_ENTRIES,
};
