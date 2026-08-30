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
int xdp_flow_load_balancer(struct xdp_md *ctx) {
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

    unsigned int sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else { // UDP
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    }

    __u32 hash = (ip->saddr ^ ip->daddr ^ (sport << 16 | dport) ^ ip->protocol) & 1;

    unsigned char *mac = bpf_map_lookup_elem(&backend_macs_1, &hash);
    if (mac) {
        __builtin_memcpy(eth->h_dest, mac, ETH_ALEN);
    }

    __u32 dev_idx = hash;
    int ret = bpf_redirect_map(&backend_devmap_1, &dev_idx, 0);
    if (ret == 0)
        return XDP_REDIRECT;
    else
        return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
