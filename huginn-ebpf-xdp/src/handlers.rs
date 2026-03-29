#![allow(unsafe_code)]

use aya_ebpf::programs::XdpContext;
use core::mem;

use crate::constants::*;
use crate::headers::{EthHdr, Ip6Hdr, IpHdr, TcpHdr, VlanHdr};
use crate::helpers::ptr_at;
use crate::signals::tcp_syn;

/// XDP pipeline: parse L2/L3/L4 and dispatch to each signal's handler.
///
/// Handles both IPv4 (`ETH_P_IP`) and IPv6 (`ETH_P_IPV6`) TCP SYN packets.
pub fn try_xdp_syn(ctx: &XdpContext) -> Result<(), ()> {
    let mut offset = 0usize;

    // ── Ethernet ──────────────────────────────────────────────────────────────
    // SAFETY: ptr_at checked bounds; we only deref when Some.
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

    if eth_type == ETH_P_IP {
        return handle_ipv4(ctx, offset);
    }
    if eth_type == ETH_P_IPV6 {
        return handle_ipv6(ctx, offset);
    }

    Ok(())
}

/// Parse IPv4 header and dispatch TCP SYN to `handle_tcp_syn_v4`.
fn handle_ipv4(ctx: &XdpContext, mut offset: usize) -> Result<(), ()> {
    // ── IPv4 ──────────────────────────────────────────────────────────────────
    // SAFETY: ptr_at checked bounds.
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

    // SAFETY: read_volatile required for loader-patched globals so the compiler does not cache.
    let dst_ip_val = unsafe { core::ptr::read_volatile(&tcp_syn::dst_ip) };
    if dst_ip_val != 0 && unsafe { (*ip).daddr } != dst_ip_val {
        return Ok(());
    }

    offset = offset.saturating_add(ip_hdr_len.saturating_sub(mem::size_of::<IpHdr>()));

    // ── TCP ───────────────────────────────────────────────────────────────────
    // SAFETY: ptr_at checked bounds.
    let tcp = unsafe { ptr_at::<TcpHdr>(ctx, offset).ok_or(())? };

    let tcp_hdr_len = unsafe { usize::from((*tcp).doff()).saturating_mul(4) };
    if tcp_hdr_len < mem::size_of::<TcpHdr>() {
        tcp_syn::increment_syn_malformed_v4();
        return Ok(());
    }

    // SAFETY: read_volatile for loader-patched global.
    let dst_port_val = unsafe { core::ptr::read_volatile(&tcp_syn::dst_port) };
    if dst_port_val != 0 && unsafe { (*tcp).dest } != dst_port_val {
        return Ok(());
    }

    if unsafe { !(*tcp).syn() || (*tcp).ack() } {
        return Ok(());
    }

    // Only TCP SYN (no ACK) matching dst_ip/dst_port reach here. Invalid or non-SYN packets
    // are filtered above with return Ok(()) and never call the handler.
    // SAFETY: ip and tcp were validated by ptr_at and bounds; valid for the duration of this call.
    let ip_ref = unsafe { &*ip };
    let tcp_ref = unsafe { &*tcp };
    // On MapInsertFailed we still pass the packet. The handler increments syn_insert_failures;
    // the agent/proxy reads it via EbpfProbe::syn_insert_failures_count() and can expose it as a metric.
    tcp_syn::handle_tcp_syn_v4(ctx, ip_ref, tcp_ref, ip_hdr_len).map_err(|_| ())
}

/// Parse IPv6 header and dispatch TCP SYN to `handle_tcp_syn_v6`.
///
/// Note: extension headers are not traversed. Only packets where the first
/// `nexthdr` is TCP (6) are captured; packets with extension headers before
/// TCP are passed without fingerprinting (future improvement).
fn handle_ipv6(ctx: &XdpContext, mut offset: usize) -> Result<(), ()> {
    // ── IPv6 ──────────────────────────────────────────────────────────────────
    // SAFETY: ptr_at checked bounds.
    let ip6 = unsafe { ptr_at::<Ip6Hdr>(ctx, offset).ok_or(())? };
    offset = offset.saturating_add(mem::size_of::<Ip6Hdr>());

    if unsafe { (*ip6).nexthdr } != IPPROTO_TCP {
        return Ok(());
    }

    // IPv6 destination address filter (all-zeros = accept any).
    // SAFETY: read_volatile for loader-patched global array.
    let dst_ip_v6_val = unsafe { core::ptr::read_volatile(&tcp_syn::dst_ip_v6) };
    let is_zero = dst_ip_v6_val.iter().all(|&b| b == 0);
    if !is_zero {
        let daddr = unsafe { (*ip6).daddr };
        if daddr != dst_ip_v6_val {
            return Ok(());
        }
    }

    // ── TCP ───────────────────────────────────────────────────────────────────
    // SAFETY: ptr_at checked bounds.
    let tcp = unsafe { ptr_at::<TcpHdr>(ctx, offset).ok_or(())? };

    let tcp_hdr_len = unsafe { usize::from((*tcp).doff()).saturating_mul(4) };
    if tcp_hdr_len < mem::size_of::<TcpHdr>() {
        tcp_syn::increment_syn_malformed_v6();
        return Ok(());
    }

    // SAFETY: read_volatile for loader-patched global.
    let dst_port_val = unsafe { core::ptr::read_volatile(&tcp_syn::dst_port) };
    if dst_port_val != 0 && unsafe { (*tcp).dest } != dst_port_val {
        return Ok(());
    }

    if unsafe { !(*tcp).syn() || (*tcp).ack() } {
        return Ok(());
    }

    // SAFETY: ip6 and tcp were validated by ptr_at and bounds; valid for the duration of this call.
    let ip6_ref = unsafe { &*ip6 };
    let tcp_ref = unsafe { &*tcp };
    tcp_syn::handle_tcp_syn_v6(ctx, ip6_ref, tcp_ref).map_err(|_| ())
}
