use super::maps::{
    increment_syn_captured_v4, increment_syn_captured_v6, increment_syn_insert_failures_v4,
    increment_syn_insert_failures_v6, read_and_increment_syn_counter, tcp_syn_map_v4,
    tcp_syn_map_v6,
};
use aya_ebpf::programs::XdpContext;
use core::mem;
use huginn_ebpf_common::constants::TCPOPT_MAXLEN;
use huginn_ebpf_common::headers::{Ip4Hdr, Ip6Hdr, TcpHdr};
use huginn_ebpf_common::quirk_bits::{
    compute_v4 as compute_quirks_v4, compute_v6 as compute_quirks_v6,
};
use huginn_ebpf_common::{make_key_v4, make_key_v6, SynRawDataV4, SynRawDataV6};

#[derive(Clone, Copy)]
pub enum TcpSynError {
    MapInsertFailed,
}

#[allow(unsafe_code)]
pub fn handle_tcp_syn_v4(
    ctx: &XdpContext,
    ip: &Ip4Hdr,
    tcp: &TcpHdr,
    ip_hdr_len: usize,
) -> Result<(), TcpSynError> {
    // Must stay inline so the BPF verifier tracks packet bounds in this frame.
    // SAFETY: tcp is valid packet memory; options start immediately after the header.
    let tcp_hdr_len = usize::from(tcp.doff()).saturating_mul(4);
    let declared_optlen = tcp_hdr_len
        .saturating_sub(mem::size_of::<TcpHdr>())
        .min(TCPOPT_MAXLEN);

    let opts_ptr = unsafe { (tcp as *const TcpHdr as *const u8).add(mem::size_of::<TcpHdr>()) };
    let data_end = ctx.data_end();
    let mut options = [0u8; 40];
    let mut actual_copied: usize = 0;
    for (i, slot) in options.iter_mut().enumerate().take(declared_optlen) {
        let byte_ptr = unsafe { opts_ptr.add(i) };
        let next_ptr = unsafe { byte_ptr.add(1) };
        if next_ptr as usize > data_end {
            break;
        }
        // SAFETY: next_ptr <= data_end checked above.
        *slot = unsafe { *byte_ptr };
        actual_copied = actual_copied.saturating_add(1);
    }

    finish_tcp_syn_v4(ip, tcp, ip_hdr_len, options, actual_copied as u8)
}

// Shared by XDP (direct packet access) and TC (`bpf_skb_load_bytes`). No packet access here.
#[inline(always)]
pub fn finish_tcp_syn_v4(
    ip: &Ip4Hdr,
    tcp: &TcpHdr,
    ip_hdr_len: usize,
    options: [u8; 40],
    optlen: u8,
) -> Result<(), TcpSynError> {
    let tick = read_and_increment_syn_counter();
    let quirks = compute_quirks_v4(ip, tcp);

    let syn_raw_data = SynRawDataV4 {
        src_addr: ip.saddr,
        src_port: tcp.source,
        window: tcp.window,
        optlen,
        ip_tos: ip.tos,
        ip_ttl: ip.ttl,
        ip_olen: ip_hdr_len.saturating_sub(mem::size_of::<Ip4Hdr>()) as u8,
        options,
        quirks,
        tick,
    };

    let key = make_key_v4(ip.saddr, tcp.source);
    if tcp_syn_map_v4.insert(key, syn_raw_data, 0).is_err() {
        increment_syn_insert_failures_v4();
        return Err(TcpSynError::MapInsertFailed);
    }
    increment_syn_captured_v4();
    Ok(())
}

#[allow(unsafe_code)]
pub fn handle_tcp_syn_v6(ctx: &XdpContext, ip6: &Ip6Hdr, tcp: &TcpHdr) -> Result<(), TcpSynError> {
    let tcp_hdr_len = usize::from(tcp.doff()).saturating_mul(4);
    let declared_optlen = tcp_hdr_len
        .saturating_sub(mem::size_of::<TcpHdr>())
        .min(TCPOPT_MAXLEN);

    let opts_ptr = unsafe { (tcp as *const TcpHdr as *const u8).add(mem::size_of::<TcpHdr>()) };
    let data_end = ctx.data_end();
    let mut options = [0u8; 40];
    let mut actual_copied: usize = 0;
    for (i, slot) in options.iter_mut().enumerate().take(declared_optlen) {
        let byte_ptr = unsafe { opts_ptr.add(i) };
        let next_ptr = unsafe { byte_ptr.add(1) };
        if next_ptr as usize > data_end {
            break;
        }
        // SAFETY: next_ptr <= data_end checked above.
        *slot = unsafe { *byte_ptr };
        actual_copied = actual_copied.saturating_add(1);
    }

    finish_tcp_syn_v6(ip6, tcp, options, actual_copied as u8)
}

#[inline(always)]
pub fn finish_tcp_syn_v6(
    ip6: &Ip6Hdr,
    tcp: &TcpHdr,
    options: [u8; 40],
    optlen: u8,
) -> Result<(), TcpSynError> {
    let tick = read_and_increment_syn_counter();
    let quirks = compute_quirks_v6(ip6, tcp);

    let syn_raw_data = SynRawDataV6 {
        src_addr: ip6.saddr,
        src_port: tcp.source,
        window: tcp.window,
        optlen,
        ip_tos: ip6.traffic_class(),
        ip_ttl: ip6.hop_limit,
        _pad: 0,
        options,
        quirks,
        tick,
    };

    let key = make_key_v6(ip6.saddr, tcp.source);
    if tcp_syn_map_v6.insert(key, syn_raw_data, 0).is_err() {
        increment_syn_insert_failures_v6();
        return Err(TcpSynError::MapInsertFailed);
    }
    increment_syn_captured_v6();
    Ok(())
}
