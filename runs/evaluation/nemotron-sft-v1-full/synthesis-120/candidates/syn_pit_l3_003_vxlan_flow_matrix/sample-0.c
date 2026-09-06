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
    __u8  proto;
    __u8  pad[3];
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
int xdp_vxlan_telemetry_syn_pit_l3_003_vxlan_flow_matrix(struct xdp_md *ctx) {
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

    __u32 vni = 0;
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        if (udp->dest == bpf_htons(4789)) {
            vni = bpf_ntohl(udp->source) & 0xFFFFFF;
        }
    }

    struct vxlan_flow_key key = {};
    key.vni = vni;
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }

    struct flow_stats *stats = bpf_map_lookup_elem(&vxlan_matrix_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->pkts, 1);
        __sync_fetch_and_add(&stats->bytes, (__u64)data_end - (__u64)data);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
