// go:build ignore
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// XDP program for TCP SYN fingerprinting.
// Captures TCP SYN packets and stores raw handshake data in a BPF LRU hash map,
// keyed by (src_ip, src_port). Adapted from ebpf-web-fingerprint (robalb).
// TLS parsing is intentionally excluded.

// clang-format off
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "headers/bpf_helpers.h"
#include "headers/bpf_endian.h"
// clang-format on

char __license[] SEC("license") = "Dual MIT/GPL";

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

/*
 * Maximum bytes of TCP options we copy from the SYN packet.
 * TCP options field is at most 40 bytes (header max 60 bytes - 20 fixed).
 */
#define TCPOPT_MAXLEN 40

/*
 * TCP destination port the proxy listens on (network byte order).
 * Patched at load time by EbpfLoader::set_global before the kernel loads the program.
 * 0 = no port filter (capture all TCP SYN).
 * Must be volatile const so clang places it in .rodata (readable by set_global).
 */
volatile const __be16 dst_port = 0;

/*
 * Destination IP the proxy listens on (network byte order).
 * Patched at load time by EbpfLoader::set_global before the kernel loads the program.
 * 0 = no IP filter (capture all destinations, e.g. listen on 0.0.0.0).
 * Must be volatile const so clang places it in .rodata (readable by set_global).
 */
volatile const __be32 dst_ip = 0;

/*
 * Data extracted from each TCP SYN packet.
 * Mirror of the Rust SynRawData struct — layout must match exactly.
 *
 * Layout (64 bytes total):
 *   offset  0: src_addr  (4)
 *   offset  4: src_port  (2)
 *   offset  6: window    (2)
 *   offset  8: optlen    (2)  — TCP options length
 *   offset 10: ip_ttl    (1)
 *   offset 11: ip_olen   (1)  — IP options length: ip->ihl*4 - 20
 *   offset 12: options   (40)
 *   offset 52: _pad2     (4) — align tick to 8-byte boundary
 *   offset 56: tick      (8)
 */
struct tcp_syn_val {
    __be32 src_addr;               /* client IP (network byte order) */
    __be16 src_port;               /* client port (network byte order) */
    __be16 window;                 /* TCP window size */
    __u16  optlen;                 /* length of the TCP options captured */
    __u8   ip_ttl;                 /* IP TTL */
    __u8   ip_olen;                /* IP options length in bytes (ip->ihl*4 - 20) */
    __u8   options[TCPOPT_MAXLEN]; /* raw TCP options bytes */
    __u8   _pad2[4];               /* align tick to 8-byte boundary */
    __u64  tick;                   /* global SYN counter at capture time */
};

/*
 * BPF LRU hash map: keyed by (src_ip << 16 | src_port) → SYN data.
 * 8192 entries covers concurrent connections; LRU evicts stale entries.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct tcp_syn_val);
} tcp_syn_map SEC(".maps");

/*
 * Monotonic SYN counter — single element ARRAY used as a global tick.
 * Incremented atomically on every captured SYN. Stored in each map entry
 * so userspace can detect stale lookups (entries whose tick is far behind
 * the current counter were captured a long time ago and may belong to a
 * different connection on the same src_ip:src_port).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syn_counter SEC(".maps");


/*
 * Build the map key from source IP and source port.
 * Both values are in network byte order as stored in the packet.
 */
static __u64 __always_inline make_key(__u32 ip, __u16 port) {
    return ((__u64)ip << 16) | port;
}

/*
 * VLAN header mirror (linux/if_vlan.h not always in UAPI).
 */
struct _vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto) {
    return !!(h_proto == __constant_htons(ETH_P_8021Q) ||
              h_proto == __constant_htons(ETH_P_8021AD));
}

static void __always_inline handle_tcp_syn(struct iphdr *ip,
                                           struct tcphdr *tcp,
                                           void *data_end,
                                           __u32 ip_hdr_len) {
    __u16 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp))
        return;

    /* Atomically increment the global SYN counter and capture its value. */
    __u64 tick = 0;
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&syn_counter, &zero);
    if (counter)
        tick = __sync_fetch_and_add(counter, 1);

    struct tcp_syn_val val = {
        .src_addr = ip->saddr,
        .src_port = tcp->source,
        .window   = tcp->window,
        .optlen   = tcp_hdr_len - sizeof(*tcp),
        .ip_ttl   = ip->ttl,
        .ip_olen  = (__u8)(ip_hdr_len - sizeof(*ip)), /* IP options: ihl*4 - 20 */
        ._pad2    = {0},
        .tick     = tick,
    };

    __u8 *options = (__u8 *)(tcp + 1);
    for (__u32 i = 0;
         i < TCPOPT_MAXLEN && i < val.optlen && (void *)options + i < data_end;
         ++i) {
        val.options[i] = options[i];
    }

    __u64 key = make_key(ip->saddr, tcp->source);
    bpf_map_update_elem(&tcp_syn_map, &key, &val, BPF_ANY);
}

SEC("xdp")
int huginn_xdp_syn(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *head     = data;

    // ── Ethernet ──────────────────────────────────────────────────
    struct ethhdr *eth = head;
    head += sizeof(*eth);
    if (head + (2 * sizeof(struct _vlan_hdr)) > data_end)
        return XDP_PASS;

    __u16 eth_type = eth->h_proto;

    if (proto_is_vlan(eth_type)) {
        struct _vlan_hdr *vlan = head;
        head += sizeof(*vlan);
        eth_type = vlan->h_vlan_encapsulated_proto;
    }
    if (proto_is_vlan(eth_type)) {
        struct _vlan_hdr *vlan = head;
        head += sizeof(*vlan);
        eth_type = vlan->h_vlan_encapsulated_proto;
    }

    if (eth_type != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // ── IPv4 ──────────────────────────────────────────────────────
    struct iphdr *ip = head;
    head += sizeof(*ip);
    if (head > data_end)
        return XDP_PASS;

    if (ip->frag_off & __constant_htons(IP_MF | IP_OFFSET))
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    if (dst_ip != 0 && ip->daddr != dst_ip)
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return XDP_PASS;

    head += ip_hdr_len - sizeof(*ip);

    // ── TCP ───────────────────────────────────────────────────────
    struct tcphdr *tcp = head;
    head += sizeof(*tcp);
    if (head > data_end)
        return XDP_PASS;

    if (dst_port != 0 && tcp->dest != dst_port)
        return XDP_PASS;

    // Only capture TCP SYN (not SYN+ACK)
    if (tcp->syn && !tcp->ack)
        handle_tcp_syn(ip, tcp, data_end, ip_hdr_len);

    return XDP_PASS;
}
