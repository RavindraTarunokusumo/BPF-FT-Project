/* XDP Flow Cache Accelerator
 * Exact-match 5-tuple flow cache lookup and redirect
 * Copyright (C) 2024  Your Name or Organization
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* 5-tuple flow key structure */
struct flow_key {
    __be32 src_ip;     /* Source IP address */
    __be32 dst_ip;     /* Destination IP address */
    __be16 src_port;   /* Source port */
    __be16 dst_port;   /* Destination port */
    __u8  proto;     /* IP protocol (TCP/UDP) */
};

/* Hash map for flow cache lookup */
struct bpf_map_def __attribute__((section("map_def"))) flow_cache_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(__u32),
    .max_entries = 2048,
    .flags = 0,
};

/* XDP program entry point */
SEC("xdp")
int xdp_flow_cache(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet frame minimum size */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Check for IPv4 protocol */
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IP header presence */
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end)
        return XDP_PASS;

    /* Only handle TCP and UDP protocols */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Verify transport layer header fits within frame */
    void *transport = data + sizeof(struct ethhdr) + (ip->ihl * 4);
    if (transport > data_end)
        return XDP_PASS;

    /* Build 5-tuple flow key */
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .proto = ip->protocol,
    };

    /* Extract ports based on protocol */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if (transport + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else { /* IPPROTO_UDP */
        struct udphdr *udp = transport;
        if (transport + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }

    /* Perform exact-match lookup in flow cache */
    __u32 *egress_ifindex = bpf_map_lookup_elem(&flow_cache_map, &key);
    if (egress_ifindex) {
        /* Cache hit: redirect packet to cached egress interface */
        return bpf_redirect(*egress_ifindex, 0);
    }

    /* Cache miss or non-IP traffic: pass to kernel slow-path */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
