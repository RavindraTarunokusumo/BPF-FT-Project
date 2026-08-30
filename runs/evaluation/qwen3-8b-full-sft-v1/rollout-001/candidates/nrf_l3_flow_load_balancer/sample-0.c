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
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, unsigned char[ETH_ALEN]);
} backend_macs_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} backend_devmap_1 SEC(".maps");

SEC("xdp")
int xdp_flow_load_balancer_nrf_l3(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        unsigned int tcp_hdr_len = ip->protocol == IPPROTO_TCP ? ip->tlc : 0;
        if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)ip + ip_hdr_len + tcp_hdr_len > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        __u16 sport = tcp->source;
        __u16 dport = tcp->dest;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        __u32 saddr = ip->saddr;
        __u32 daddr = ip->daddr;
        __u8  proto = ip->protocol;
        __u32 hash = (saddr ^ daddr ^ (sport << 16 | dport) ^ proto) & 1;
        unsigned char *mac = bpf_map_lookup_elem(&backend_macs_1, &hash);
        if (mac) {
            __builtin_memcpy(eth->h_dest, mac, ETH_ALEN);
        }
        __u32 dev_idx = hash;
        __u32 *dev = bpf_map_lookup_elem(&backend_devmap_1, &dev_idx);
        if (dev) {
            return bpf_redirect_map(&backend_devmap_1, dev_idx, 0);
        }
        return XDP_PASS;
    } else { // UDP
        __u32 saddr = ip->saddr;
        __u32 daddr = ip->daddr;
        __u8  proto = ip->protocol;
        __u16 sport = ip->check;
        __u16 dport = ip->ttl;
        __u32 hash = (saddr ^ daddr ^ (sport << 16 | dport) ^ proto) & 1;
        unsigned char *mac = bpf_map_lookup_elem(&backend_macs_1, &hash);
        if (mac) {
            __builtin_memcpy(eth->h_dest, mac, ETH_ALEN);
        }
        __u32 dev_idx = hash;
        __u32 *dev = bpf_map_lookup_elem(&backend_devmap_1, &dev_idx);
        if (dev) {
            return bpf_redirect_map(&backend_devmap_1, dev_idx, 0);
        }
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
<|im_end|>
