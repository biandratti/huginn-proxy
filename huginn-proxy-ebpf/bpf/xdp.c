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
 * TCP destination port the proxy listens on.
 * Injected at program load time by the Rust userspace code.
 * Defaults to 443 when not set.
 */
volatile __be16 dst_port = 0;

/*
 * Destination IP the proxy listens on (network byte order).
 * Injected at program load time by the Rust userspace code.
 * Defaults to 0.0.0.0 when not set.
 */
volatile __be32 dst_ip = 0;

/*
 * Data extracted from each TCP SYN packet.
 * Mirror of the Rust SynRawData struct — layout must match exactly.
 */
struct tcp_syn_val {
    __be32 src_addr;      /* client IP (network byte order) */
    __be16 src_port;      /* client port (network byte order) */
    __be16 window;        /* TCP window size */
    __u16  optlen;        /* length of the TCP options captured */
    __u8   ip_ttl;        /* IP TTL */
    __u8   _pad;          /* explicit padding — Rust struct has this too */
    __u8   options[TCPOPT_MAXLEN]; /* raw TCP options bytes */
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
                                           void *data_end) {
    __u16 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(*tcp))
        return;

    struct tcp_syn_val val = {
        .src_addr = ip->saddr,
        .src_port = tcp->source,
        .window   = tcp->window,
        .optlen   = tcp_hdr_len - sizeof(*tcp),
        .ip_ttl   = ip->ttl,
        ._pad     = 0,
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
        handle_tcp_syn(ip, tcp, data_end);

    return XDP_PASS;
}
