#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

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
    __type(key, struct vxlan_flow_key);
    __type(value, struct flow_stats);
    __uint(max_entries, 2048);
} vxlan_matrix_map SEC(".maps");

SEC("xdp")
int xdp_vxlan_flow_matrix(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    __u32 *vx = (void *)(udp + 1);
    if ((void *)(vx + 2) > data_end)
        return XDP_PASS;

    __u32 vni = bpf_ntohl(*(vx + 1)) >> 8;

    struct ethhdr *inner_eth = (void *)(vx + 2);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;
    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    int inner_ip_len = inner_ip->ihl * 4;
    if (inner_ip_len < sizeof(struct iphdr) || (void *)inner_ip + inner_ip_len > data_end)
        return XDP_PASS;

    __be16 sport = 0, dport = 0;
    if (inner_ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)inner_ip + inner_ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (inner_ip->protocol == IPPROTO_UDP) {
        struct udphdr *inner_udp = (void *)inner_ip + inner_ip_len;
        if ((void *)(inner_udp + 1) > data_end)
            return XDP_PASS;
        sport = inner_udp->source;
        dport = inner_udp->dest;
    } else {
        return XDP_PASS;
    }

    struct vxlan_flow_key key = {
        .vni = vni,
        .src_ip = inner_ip->saddr,
        .dst_ip = inner_ip->daddr,
        .src_port = sport,
        .dst_port = dport,
        .proto = inner_ip->protocol,
        .pad = {0, 0, 0},
    };

    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
    struct flow_stats *st = bpf_map_lookup_elem(&vxlan_matrix_map, &key);
    if (!st) {
        struct flow_stats new_st = { .pkts = 1, .bytes = pkt_len };
        bpf_map_update_elem(&vxlan_matrix_map, &key, &new_st, BPF_ANY);
    } else {
        st->pkts += 1;
        st->bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
