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

struct path_metrics {
    __u64 pkts;
    __u64 bytes;
    __u32 hops;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct path_metrics);
} srv6_path_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_009_srv6_path_latency_telemetry(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_ROUTING)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct ipv6hdr *ipv6 = (void *)ip + ip_hdr_len;
    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    if (ipv6->nexthdr != IPPROTO_ROUTING)
        return XDP_PASS;

    unsigned int ip6_hdr_len = ipv6->hdr_len * 4;
    if (ip6_hdr_len < sizeof(struct ipv6hdr) || (void *)ipv6 + ip6_hdr_len > data_end)
        return XDP_PASS;

    struct ip_rthdr *rth = (void *)ipv6 + ip6_hdr_len;
    if ((void *)(rth + 1) > data_end)
        return XDP_PASS;

    if (rth->rth_len < sizeof(struct ip_rthdr) || rth->rth_len % 4 != 0)
        return XDP_PASS;

    __u32 hash = 0;
    struct ip_rthdr *r = rth;
    while ((void *)r < (void *)r + rth->rth_len) {
        struct ip_rtspec *s = (void *)r + sizeof(struct ip_rthdr);
        if ((void *)s + 16 > (void *)r + rth->rth_len)
            break;
        __u8 *sid = (void *)s + 8;
        for (int i = 0; i < 16; i++)
            hash = (hash * 127 + sid[i]) % 1024;
        r = (void *)s + 16;
    }

    struct path_metrics *p = bpf_map_lookup_elem(&srv6_path_map, &hash);
    if (p) {
        p->pkts += 1;
        p->bytes += ( (__u64)ip->tot_len );
        p->hops += ( (__u32)r - (void *)ipv6 - ip6_hdr_len ) / 16 + 1;
    } else {
        struct path_metrics initial = {
            .pkts = 1,
            .bytes = ( (__u64)ip->tot_len ),
            .hops = ( (__u32)r - (void *)ipv6 - ip6_hdr_len ) / 16 + 1,
        };
        bpf_map_update_elem(&srv6_path_map, &hash, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
