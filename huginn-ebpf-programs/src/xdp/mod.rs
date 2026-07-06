//! XDP capture pipeline.
//!
//! Parses L2/L3/L4 via **direct packet access** (`packet::ptr_at` + raw deref) and dispatches TCP
//! SYNs to the shared `signals::tcp_syn` handlers. This is the fast, driver/generic-XDP path used
//! on physical/veth interfaces. On VLAN/bond interfaces use the TC path instead (see `crate::tc`).
//!
//! Direct packet access is intrinsic to XDP and the verifier requires the bounds-check-then-deref
//! idiom, so this module retains `unsafe`; `packet.rs` confines the pointer arithmetic. Each fn that
//! dereferences packet pointers carries its own `#[allow(unsafe_code)]` + `// SAFETY` note.

mod packet;

use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::{debug, warn};
use core::mem;

use crate::constants::*;
use crate::headers::{EthHdr, Ip4Hdr, Ip6Hdr, TcpHdr, VlanHdr};
use crate::signals::tcp_syn;
use packet::ptr_at;

/// XDP pipeline: parse L2/L3/L4 and dispatch to each signal's handler.
///
/// Handles both IPv4 (`ETH_P_IPV4`) and IPv6 (`ETH_P_IPV6`) TCP SYN packets.
#[allow(unsafe_code)]
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

    if eth_type == ETH_P_IPV4 {
        return handle_ipv4(ctx, offset);
    }
    if eth_type == ETH_P_IPV6 {
        return handle_ipv6(ctx, offset);
    }

    Ok(())
}

/// Parse IPv4 header and dispatch TCP SYN to `handle_tcp_syn_v4`.
#[allow(unsafe_code)]
fn handle_ipv4(ctx: &XdpContext, mut offset: usize) -> Result<(), ()> {
    // ── IPv4 ──────────────────────────────────────────────────────────────────
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

    // ── TCP ───────────────────────────────────────────────────────────────────
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

    // Only TCP SYN (no ACK) matching dst_ip_v4/dst_port reach here. Invalid or non-SYN packets
    // are filtered above with return Ok(()) and never call the handler.
    // SAFETY: ip and tcp were validated by ptr_at and bounds; valid for the duration of this call.
    let ip_ref = unsafe { &*ip };
    let tcp_ref = unsafe { &*tcp };
    // On MapInsertFailed we still pass the packet. The handler increments syn_insert_failures;
    // the agent/proxy reads it via EbpfProbe::syn_insert_failures_count() and can expose it as a metric.
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

/// Parse IPv6 header and dispatch TCP SYN to `handle_tcp_syn_v6`.
///
/// Only packets where `nexthdr` in the fixed IPv6 header is directly TCP (6)
/// are fingerprinted. Packets with extension headers before TCP are passed
/// without fingerprinting. Possible spoofing risk: a malicious actor could
/// send a packet with an extension header before TCP to bypass the fingerprinting.
#[allow(unsafe_code)]
fn handle_ipv6(ctx: &XdpContext, mut offset: usize) -> Result<(), ()> {
    // ── IPv6 ──────────────────────────────────────────────────────────────────
    // SAFETY: ptr_at checked bounds.
    let ip6 = unsafe { ptr_at::<Ip6Hdr>(ctx, offset).ok_or(())? };
    offset = offset.saturating_add(mem::size_of::<Ip6Hdr>());

    if unsafe { (*ip6).nexthdr } != IPPROTO_TCP {
        return Ok(());
    }

    // IPv6 destination address filter (all-zeros = accept any).
    let dst_ip_v6_val = tcp_syn::dst_ip_v6();
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

    let dst_port_val = tcp_syn::dst_port();
    if dst_port_val != 0 && unsafe { (*tcp).dest } != dst_port_val {
        return Ok(());
    }

    if unsafe { !(*tcp).syn() || (*tcp).ack() } {
        return Ok(());
    }

    // SAFETY: ip6 and tcp were validated by ptr_at and bounds; valid for the duration of this call.
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
