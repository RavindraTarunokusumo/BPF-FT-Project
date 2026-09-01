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

struct flow_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

static __u32 hash_flow(struct flow_tuple *t) {
    __u32 hash = 0x811C9DC5;
    hash = (hash ^ t->saddr) * 0x01000000 + 0x811C9DC5;
    hash = (hash ^ t->daddr) * 0x01000000 + 0x811C9DC5;
    hash = (hash ^ t->sport) * 0x01000000 + 0x811C9DC5;
    hash = (hash ^ t->dport) * 0x01000000 + 0x811C9DC5;
    hash = (hash ^ t->proto) * 0x01000000 + 0x811C9DC5;
    return hash;
}

SEC("xdp")
int xdp_route_syn_nrf_l3_001_maglev_consistent_hash_lb(struct xdp_md *ctx) {
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

    struct flow_tuple t = {};
    t.saddr = ip->saddr;
    t.daddr = ip->daddr;
    t.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        t.sport = tcp->source;
        t.dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        t.sport = udp->source;
        t.dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    __u32 hash = hash_flow(&t);
    int backend_id = hash % 4;
    return bpf_redirect(100 + backend_id, 0);
}

char _license[] SEC("license") = "GPL";
