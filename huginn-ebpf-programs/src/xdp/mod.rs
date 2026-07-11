//! XDP capture pipeline. Direct packet access; use TC on VLAN/bond edges.

mod packet;

use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::{debug, warn};
use core::mem;

use huginn_ebpf_common::constants::*;
use huginn_ebpf_common::headers::{EthHdr, Ip4Hdr, Ip6Hdr, TcpHdr, VlanHdr};
use packet::ptr_at;

use crate::signals::tcp_syn;

#[allow(unsafe_code)]
pub fn try_xdp_syn(ctx: &XdpContext) -> Result<(), ()> {
    let mut offset = 0usize;

    // SAFETY: ptr_at checked bounds; we only deref when Some.
    let eth = unsafe { ptr_at::<EthHdr>(ctx, offset).ok_or(())? };
    offset = offset.saturating_add(mem::size_of::<EthHdr>());

    let mut eth_type = unsafe { (*eth).h_proto };

    if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
        let vlan = unsafe { ptr_at::<VlanHdr>(ctx, offset).ok_or(())? };
        offset = offset.saturating_add(mem::size_of::<VlanHdr>());
        eth_type = unsafe { (*vlan).encapsulated_proto };
    }
    if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
        let vlan = unsafe { ptr_at::<VlanHdr>(ctx, offset).ok_or(())? };
        offset = offset.saturating_add(mem::size_of::<VlanHdr>());
        eth_type = unsafe { (*vlan).encapsulated_proto };
    }

    if eth_type == ETH_P_IPV4 {
        return handle_ipv4(ctx, offset);
    }
    if eth_type == ETH_P_IPV6 {
        return handle_ipv6(ctx, offset);
    }

    Ok(())
}

#[allow(unsafe_code)]
fn handle_ipv4(ctx: &XdpContext, mut offset: usize) -> Result<(), ()> {
    // SAFETY: ptr_at checked bounds.
    let ip = unsafe { ptr_at::<Ip4Hdr>(ctx, offset).ok_or(())? };

    let ip_hdr_len = unsafe { usize::from((*ip).ihl()).saturating_mul(4) };
    if ip_hdr_len < mem::size_of::<Ip4Hdr>() {
        return Ok(());
    }
    offset = offset.saturating_add(mem::size_of::<Ip4Hdr>());

    let frag_off = unsafe { (*ip).frag_off };
    if frag_off & (IP_MF | IP_OFFSET) != 0 {
        return Ok(());
    }

    if unsafe { (*ip).protocol } != IPPROTO_TCP {
        return Ok(());
    }

    let dst_ip_v4_val = tcp_syn::dst_ip_v4();
    if dst_ip_v4_val != 0 && unsafe { (*ip).daddr } != dst_ip_v4_val {
        return Ok(());
    }

    offset = offset.saturating_add(ip_hdr_len.saturating_sub(mem::size_of::<Ip4Hdr>()));

    // SAFETY: ptr_at checked bounds.
    let tcp = unsafe { ptr_at::<TcpHdr>(ctx, offset).ok_or(())? };

    let tcp_hdr_len = unsafe { usize::from((*tcp).doff()).saturating_mul(4) };
    if tcp_hdr_len < mem::size_of::<TcpHdr>() {
        tcp_syn::increment_syn_malformed_v4();
        return Ok(());
    }

    let dst_port_val = tcp_syn::dst_port();
    if dst_port_val != 0 && unsafe { (*tcp).dest } != dst_port_val {
        return Ok(());
    }

    if unsafe { !(*tcp).syn() || (*tcp).ack() } {
        return Ok(());
    }

    // SAFETY: ip and tcp validated by ptr_at; valid for the duration of this call.
    let ip_ref = unsafe { &*ip };
    let tcp_ref = unsafe { &*tcp };
    let result = tcp_syn::handle_tcp_syn_v4(ctx, ip_ref, tcp_ref, ip_hdr_len);
    let lvl = tcp_syn::log_level();
    match result {
        Ok(()) if lvl >= tcp_syn::level::DEBUG => debug!(
            ctx,
            "xdp: captured TCP SYN v4 sport={} dport={}",
            u16::from_be(tcp_ref.source),
            u16::from_be(tcp_ref.dest)
        ),
        Err(_) if lvl >= tcp_syn::level::WARN => {
            warn!(ctx, "xdp: TCP SYN v4 map insert failed (LRU full?)")
        }
        _ => {}
    }
    result.map_err(|_| ())
}

// Only fixed-header nexthdr == TCP is fingerprinted; extension headers before TCP can bypass capture.
#[allow(unsafe_code)]
fn handle_ipv6(ctx: &XdpContext, mut offset: usize) -> Result<(), ()> {
    // SAFETY: ptr_at checked bounds.
    let ip6 = unsafe { ptr_at::<Ip6Hdr>(ctx, offset).ok_or(())? };
    offset = offset.saturating_add(mem::size_of::<Ip6Hdr>());

    if unsafe { (*ip6).nexthdr } != IPPROTO_TCP {
        return Ok(());
    }

    let dst_ip_v6_val = tcp_syn::dst_ip_v6();
    let is_zero = dst_ip_v6_val.iter().all(|&b| b == 0);
    if !is_zero {
        let daddr = unsafe { (*ip6).daddr };
        if daddr != dst_ip_v6_val {
            return Ok(());
        }
    }

    // SAFETY: ptr_at checked bounds.
    let tcp = unsafe { ptr_at::<TcpHdr>(ctx, offset).ok_or(())? };

    let tcp_hdr_len = unsafe { usize::from((*tcp).doff()).saturating_mul(4) };
    if tcp_hdr_len < mem::size_of::<TcpHdr>() {
        tcp_syn::increment_syn_malformed_v6();
        return Ok(());
    }

    let dst_port_val = tcp_syn::dst_port();
    if dst_port_val != 0 && unsafe { (*tcp).dest } != dst_port_val {
        return Ok(());
    }

    if unsafe { !(*tcp).syn() || (*tcp).ack() } {
        return Ok(());
    }

    // SAFETY: ip6 and tcp validated by ptr_at; valid for the duration of this call.
    let ip6_ref = unsafe { &*ip6 };
    let tcp_ref = unsafe { &*tcp };
    let result = tcp_syn::handle_tcp_syn_v6(ctx, ip6_ref, tcp_ref);
    let lvl = tcp_syn::log_level();
    match result {
        Ok(()) if lvl >= tcp_syn::level::DEBUG => debug!(
            ctx,
            "xdp: captured TCP SYN v6 sport={} dport={}",
            u16::from_be(tcp_ref.source),
            u16::from_be(tcp_ref.dest)
        ),
        Err(_) if lvl >= tcp_syn::level::WARN => {
            warn!(ctx, "xdp: TCP SYN v6 map insert failed (LRU full?)")
        }
        _ => {}
    }
    result.map_err(|_| ())
}
