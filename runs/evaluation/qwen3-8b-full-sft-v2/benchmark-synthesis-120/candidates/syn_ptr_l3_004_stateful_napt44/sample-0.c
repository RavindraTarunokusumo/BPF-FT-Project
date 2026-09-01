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

struct napt_tuple {
    __u32 src_ip;
    __u16 src_port;
    __u16 pad;
    __u32 dst_ip;
    __u16 dst_port;
    __u16 pad2;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct napt_tuple);
    __type(value, __u32);
} napt_fwd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct napt_tuple);
    __type(value, __u32);
} napt_rev_map SEC(".maps");

SEC("xdp")
int xdp_transform_syn_ptr_l3_004_stateful_napt44(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct napt_tuple key = {};
    key.src_ip = ip->saddr;
    key.src_port = tcp->source;
    key.dst_ip = ip->daddr;
    key.dst_port = tcp->dest;

    __u32 *new_port = bpf_map_lookup_elem(&napt_fwd_map, &key);
    if (new_port) {
        tcp->source = *new_port;
        ip->saddr = bpf_htons(19851100 + (key.src_ip % 256));
        // Recalculate checksum
        __u32 csum = 0;
        ip->check = 0;
        __u16 *p = (__u16 *)ip;
        #pragma unroll
        for (int i = 0; i < 10; i++)
            csum += p[i];
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = ~csum;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
