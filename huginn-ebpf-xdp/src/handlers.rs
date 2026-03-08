#![allow(unsafe_code)]

use aya_ebpf::programs::XdpContext;
use core::mem;

use crate::constants::*;
use crate::headers::{EthHdr, IpHdr, TcpHdr, VlanHdr};
use crate::helpers::ptr_at;
use crate::signals::tcp_syn;

/// XDP pipeline: parse L2/L3/L4 and dispatch to each signal's handler.
///
/// Currently only IPv4 TCP is handled; IPv6 and other signals are added here.
pub fn try_xdp_syn(ctx: &XdpContext) -> Result<(), ()> {
    let mut offset = 0usize;

    // ── Ethernet ──────────────────────────────────────────────────────────────
    let eth = unsafe { ptr_at::<EthHdr>(ctx, offset).ok_or(())? };
    offset = offset.saturating_add(mem::size_of::<EthHdr>());

    let mut eth_type = unsafe { (*eth).h_proto };

    // Up to two VLAN tags (QinQ / 802.1ad)
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

    if eth_type != ETH_P_IP {
        return Ok(());
    }

    // ── IPv4 ──────────────────────────────────────────────────────────────────
    let ip = unsafe { ptr_at::<IpHdr>(ctx, offset).ok_or(())? };

    let ip_hdr_len = unsafe { usize::from((*ip).ihl()).saturating_mul(4) };
    if ip_hdr_len < mem::size_of::<IpHdr>() {
        return Ok(());
    }
    offset = offset.saturating_add(mem::size_of::<IpHdr>());

    let frag_off = unsafe { (*ip).frag_off };
    if frag_off & (IP_MF | IP_OFFSET) != 0 {
        return Ok(());
    }

    if unsafe { (*ip).protocol } != IPPROTO_TCP {
        return Ok(());
    }

    let dst_ip_val = unsafe { core::ptr::read_volatile(&tcp_syn::dst_ip) };
    if dst_ip_val != 0 && unsafe { (*ip).daddr } != dst_ip_val {
        return Ok(());
    }

    offset = offset.saturating_add(ip_hdr_len.saturating_sub(mem::size_of::<IpHdr>()));

    // ── TCP ───────────────────────────────────────────────────────────────────
    let tcp = unsafe { ptr_at::<TcpHdr>(ctx, offset).ok_or(())? };

    let tcp_hdr_len = unsafe { usize::from((*tcp).doff()).saturating_mul(4) };
    if tcp_hdr_len < mem::size_of::<TcpHdr>() {
        return Ok(());
    }

    let dst_port_val = unsafe { core::ptr::read_volatile(&tcp_syn::dst_port) };
    if dst_port_val != 0 && unsafe { (*tcp).dest } != dst_port_val {
        return Ok(());
    }

    if unsafe { !(*tcp).syn() || (*tcp).ack() } {
        return Ok(());
    }

    tcp_syn::handle_tcp_syn_v4(ctx, ip, tcp, ip_hdr_len)
}
