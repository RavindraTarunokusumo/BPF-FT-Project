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


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, unsigned char[ETH_ALEN]);
} gateways_27 SEC(".maps");

SEC("xdp")
int xdp_ecmp_nrf_l3_027(struct xdp_md *ctx) {
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

    if (ip->ttl <= 1)
        return XDP_DROP;

    __u32 hash = ip->saddr ^ ip->daddr ^ ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        hash ^= (tcp->source ^ tcp->dest);
    }

    __u32 gw_idx = hash % 4;
    unsigned char *gw_mac = bpf_map_lookup_elem(&gateways_27, &gw_idx);
    if (!gw_mac)
        return XDP_PASS;

    __builtin_memcpy(eth->h_dest, gw_mac, ETH_ALEN);
    
    ip->ttl -= 1;
    // Simple incremental checksum adjustment
    __u32 csum = (__u32)ip->check + 0x0100;
    ip->check = (csum >= 0x10000) ? (csum - 0xFFFF) : csum;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
