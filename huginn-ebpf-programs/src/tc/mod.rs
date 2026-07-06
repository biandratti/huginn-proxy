//! TC (clsact) ingress capture pipeline for TCP SYN fingerprinting.
//!
//! Functional mirror of the XDP pipeline in `crate::xdp`, but over `TcContext`. TC ingress runs in
//! the network stack and reads packet bytes via `bpf_skb_load_bytes` (`ctx.load`), which the kernel
//! makes available even for **non-linear / GRO-merged** skbs. Returning `TC_ACT_OK` never drops the
//! packet, so it works on VLAN/bond interfaces where generic XDP drops GRO-merged data packets. See
//! `data/ebpf-vlan-tc-capture.md`.
//!
//! The capture logic (dst filter, SYN-no-ACK gate, quirks, map writes) is identical to XDP; only
//! the packet-access layer changes. The map set, names, key encoding, and value layout are reused
//! unchanged via `signals::tcp_syn`, keeping the on-disk contract byte-for-byte identical.
//!
//! Unlike `crate::xdp`, this pipeline is fully safe: `ctx.load` returns values by copy, and the
//! loader-patched globals are read through the safe accessors in `signals::tcp_syn`. No `unsafe`
//! appears here, so the module denies it outright.
#![deny(unsafe_code)]

use aya_ebpf::programs::TcContext;
use aya_log_ebpf::{debug, warn};
use core::mem;

use crate::constants::*;
use crate::headers::{EthHdr, Ip4Hdr, Ip6Hdr, TcpHdr, VlanHdr};
use crate::signals::tcp_syn;

/// TC ingress pipeline: parse L2/L3/L4 and dispatch TCP SYNs to the shared finishers.
///
/// At TC ingress the skb starts at the MAC header. On a VLAN sub-interface (e.g. `bond0.44`) the
/// 802.1Q tag is already stripped, so `EthHdr.h_proto` is the inner ethertype; on trunk interfaces
/// up to two VLAN tags are walked (parity with XDP). Any parse/bounds failure returns `Ok(())`,
/// and the caller passes the packet (`TC_ACT_OK`) regardless.
pub fn try_tc_syn(ctx: &TcContext) -> Result<(), ()> {
    let mut offset = 0usize;

    // ── Ethernet ────────────────────────────────────────────────────────────────
    let eth: EthHdr = ctx.load(offset).map_err(|_| ())?;
    offset = offset.saturating_add(mem::size_of::<EthHdr>());

    let mut eth_type = eth.h_proto;

    // Up to two VLAN tags (QinQ / 802.1ad). Won't trigger on a sub-interface (tag pre-stripped).
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

/// Parse IPv4 + TCP from the skb and dispatch a SYN to `finish_tcp_syn_v4`.
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

    // ── TCP ─────────────────────────────────────────────────────────────────────
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

/// Parse IPv6 + TCP from the skb and dispatch a SYN to `finish_tcp_syn_v6`.
///
/// Like the XDP path, only packets whose fixed-header `nexthdr` is directly TCP are
/// fingerprinted; extension headers before TCP are passed without fingerprinting.
fn handle_ipv6(ctx: &TcContext, offset: usize) -> Result<(), ()> {
    let ip6: Ip6Hdr = ctx.load(offset).map_err(|_| ())?;

    if ip6.nexthdr != IPPROTO_TCP {
        return Ok(());
    }

    // IPv6 destination address filter (all-zeros = accept any).
    let dst_ip_v6_val = tcp_syn::dst_ip_v6();
    let is_zero = dst_ip_v6_val.iter().all(|&b| b == 0);
    if !is_zero && ip6.daddr != dst_ip_v6_val {
        return Ok(());
    }

    // ── TCP ─────────────────────────────────────────────────────────────────────
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

/// Read the TCP options block into a fixed 40-byte buffer, one byte at a time via `ctx.load::<u8>`.
///
/// We deliberately avoid `ctx.load_bytes(.., &mut buf)`: aya computes its length as
/// `min(buf.len(), skb_len - offset)`, which the verifier sees as a *variable* that can be `0`, and
/// `bpf_skb_load_bytes` rejects a zero-sized read (`R4 invalid zero-sized read`). Each `load::<u8>`
/// is a **constant** 1-byte `bpf_skb_load_bytes`, and the loop is bounded by the fixed 40-byte array
/// (`take(declared_optlen)`), so the program verifies. This mirrors the XDP path in
/// `signals/tcp_syn/handler.rs`. The read stops at the first out-of-bounds byte (short skb).
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
