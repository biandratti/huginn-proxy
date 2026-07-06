//! TC clsact ingress capture. GRO-safe alternative to XDP on VLAN/bond edges.

use aya_ebpf::programs::TcContext;
use aya_log_ebpf::{debug, warn};
use core::mem;

use crate::signals::tcp_syn;
use huginn_ebpf_common::constants::*;
use huginn_ebpf_common::headers::{EthHdr, Ip4Hdr, Ip6Hdr, TcpHdr, VlanHdr};

pub fn try_tc_syn(ctx: &TcContext) -> Result<(), ()> {
    let mut offset = 0usize;

    let eth: EthHdr = ctx.load(offset).map_err(|_| ())?;
    offset = offset.saturating_add(mem::size_of::<EthHdr>());

    let mut eth_type = eth.h_proto;

    if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
        let vlan: VlanHdr = ctx.load(offset).map_err(|_| ())?;
        offset = offset.saturating_add(mem::size_of::<VlanHdr>());
        eth_type = vlan.encapsulated_proto;
    }
    if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
        let vlan: VlanHdr = ctx.load(offset).map_err(|_| ())?;
        offset = offset.saturating_add(mem::size_of::<VlanHdr>());
        eth_type = vlan.encapsulated_proto;
    }

    if eth_type == ETH_P_IPV4 {
        return handle_ipv4(ctx, offset);
    }
    if eth_type == ETH_P_IPV6 {
        return handle_ipv6(ctx, offset);
    }

    Ok(())
}

fn handle_ipv4(ctx: &TcContext, offset: usize) -> Result<(), ()> {
    let ip: Ip4Hdr = ctx.load(offset).map_err(|_| ())?;

    let ip_hdr_len = usize::from(ip.ihl()).saturating_mul(4);
    if ip_hdr_len < mem::size_of::<Ip4Hdr>() {
        return Ok(());
    }

    let frag_off = ip.frag_off;
    if frag_off & (IP_MF | IP_OFFSET) != 0 {
        return Ok(());
    }

    if ip.protocol != IPPROTO_TCP {
        return Ok(());
    }

    let dst_ip_v4_val = tcp_syn::dst_ip_v4();
    if dst_ip_v4_val != 0 && ip.daddr != dst_ip_v4_val {
        return Ok(());
    }

    let tcp_offset = offset.saturating_add(ip_hdr_len);
    let tcp: TcpHdr = ctx.load(tcp_offset).map_err(|_| ())?;

    let tcp_hdr_len = usize::from(tcp.doff()).saturating_mul(4);
    if tcp_hdr_len < mem::size_of::<TcpHdr>() {
        tcp_syn::increment_syn_malformed_v4();
        return Ok(());
    }

    let dst_port_val = tcp_syn::dst_port();
    if dst_port_val != 0 && tcp.dest != dst_port_val {
        return Ok(());
    }

    if !tcp.syn() || tcp.ack() {
        return Ok(());
    }

    let opts_offset = tcp_offset.saturating_add(mem::size_of::<TcpHdr>());
    let (options, optlen) = load_tcp_options(ctx, opts_offset, tcp_hdr_len);
    let result = tcp_syn::finish_tcp_syn_v4(&ip, &tcp, ip_hdr_len, options, optlen);
    let lvl = tcp_syn::log_level();
    match result {
        Ok(()) if lvl >= tcp_syn::level::DEBUG => debug!(
            ctx,
            "tc: captured TCP SYN v4 sport={} dport={}",
            u16::from_be(tcp.source),
            u16::from_be(tcp.dest)
        ),
        Err(_) if lvl >= tcp_syn::level::WARN => {
            warn!(ctx, "tc: TCP SYN v4 map insert failed (LRU full?)")
        }
        _ => {}
    }
    result.map_err(|_| ())
}

// Only fixed-header nexthdr == TCP is fingerprinted; extension headers before TCP are skipped.
fn handle_ipv6(ctx: &TcContext, offset: usize) -> Result<(), ()> {
    let ip6: Ip6Hdr = ctx.load(offset).map_err(|_| ())?;

    if ip6.nexthdr != IPPROTO_TCP {
        return Ok(());
    }

    let dst_ip_v6_val = tcp_syn::dst_ip_v6();
    let is_zero = dst_ip_v6_val.iter().all(|&b| b == 0);
    if !is_zero && ip6.daddr != dst_ip_v6_val {
        return Ok(());
    }

    let tcp_offset = offset.saturating_add(mem::size_of::<Ip6Hdr>());
    let tcp: TcpHdr = ctx.load(tcp_offset).map_err(|_| ())?;

    let tcp_hdr_len = usize::from(tcp.doff()).saturating_mul(4);
    if tcp_hdr_len < mem::size_of::<TcpHdr>() {
        tcp_syn::increment_syn_malformed_v6();
        return Ok(());
    }

    let dst_port_val = tcp_syn::dst_port();
    if dst_port_val != 0 && tcp.dest != dst_port_val {
        return Ok(());
    }

    if !tcp.syn() || tcp.ack() {
        return Ok(());
    }

    let opts_offset = tcp_offset.saturating_add(mem::size_of::<TcpHdr>());
    let (options, optlen) = load_tcp_options(ctx, opts_offset, tcp_hdr_len);
    let result = tcp_syn::finish_tcp_syn_v6(&ip6, &tcp, options, optlen);
    let lvl = tcp_syn::log_level();
    match result {
        Ok(()) if lvl >= tcp_syn::level::DEBUG => debug!(
            ctx,
            "tc: captured TCP SYN v6 sport={} dport={}",
            u16::from_be(tcp.source),
            u16::from_be(tcp.dest)
        ),
        Err(_) if lvl >= tcp_syn::level::WARN => {
            warn!(ctx, "tc: TCP SYN v6 map insert failed (LRU full?)")
        }
        _ => {}
    }
    result.map_err(|_| ())
}

// load::<u8> per byte: bpf_skb_load_bytes rejects zero-length reads; the verifier accepts constant 1-byte loads.
#[inline(always)]
fn load_tcp_options(ctx: &TcContext, opts_offset: usize, tcp_hdr_len: usize) -> ([u8; 40], u8) {
    let declared_optlen = tcp_hdr_len
        .saturating_sub(mem::size_of::<TcpHdr>())
        .min(TCPOPT_MAXLEN);
    let mut options = [0u8; 40];
    let mut copied: usize = 0;
    for (i, slot) in options.iter_mut().enumerate().take(declared_optlen) {
        match ctx.load::<u8>(opts_offset.saturating_add(i)) {
            Ok(byte) => {
                *slot = byte;
                copied = copied.saturating_add(1);
            }
            Err(_) => break,
        }
    }
    (options, copied as u8)
}
