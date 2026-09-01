#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vxlan_flow_key {
    __u32 vni;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
    __u8 pad[3];
};

struct flow_stats {
    __u64 pkts;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct vxlan_flow_key);
    __type(value, struct flow_stats);
} vxlan_matrix_map SEC(".maps");

SEC("xdp")
int xdp_vxlan_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlan_flow_key key = {};
    key.vni = (udp->dest ^ 0x10000) >> 16;

    struct ethhdr *inner_eth = (void *)(udp + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u32 inner_ip_hdr_len = inner_ip->ihl * 4;
    if (inner_ip_hdr_len < sizeof(struct iphdr) || (void *)inner_ip + inner_ip_hdr_len > data_end)
        return XDP_PASS;

    key.src_ip = inner_ip->saddr;
    key.dst_ip = inner_ip->daddr;
    key.proto = inner_ip->protocol;

    if (inner_ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)inner_ip + inner_ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (inner_ip->protocol == IPPROTO_UDP) {
        struct udphdr *inner_udp = (void *)inner_ip + inner_ip_hdr_len;
        if ((void *)(inner_udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = inner_udp->source;
        key.dst_port = inner_udp->dest;
    } else {
        return XDP_PASS;
    }

    __u64 pkt_len = (__u64)data_end - (__u64)data;
    struct flow_stats *stats = bpf_map_lookup_elem(&vxlan_matrix_map, &key);
    if (stats) {
        stats->pkts += 1;
        stats->bytes += pkt_len;
    } else {
        struct flow_stats initial = {
            .pkts = 1,
            .bytes = pkt_len,
        };
        bpf_map_update_elem(&vxlan_matrix_map, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
