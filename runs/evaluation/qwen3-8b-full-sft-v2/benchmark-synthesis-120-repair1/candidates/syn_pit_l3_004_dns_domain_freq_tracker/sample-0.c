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

struct domain_stat {
    __u64 query_count;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct domain_stat);
} domain_freq_map SEC(".maps");

__u32 hash_dns_name(const void *name, __u32 name_len) {
    __u32 hash = 0;
    const char *p = name;
    while (name_len--) {
        hash ^= (hash * 17 + (unsigned char)*p++);
    }
    return hash;
}

SEC("xdp")
int xdp_telemetry_syn_pit_l3_004_dns_domain_freq_tracker(struct xdp_md *ctx) {
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    unsigned char *qname = (void *)(udp + 1);
    if ((void *)(qname + 100) > data_end) // DNS QNAME max 63 chars + 1 for null
        return XDP_PASS;

    __u32 hash = hash_dns_name(qname, 63);
    struct domain_stat *stat = bpf_map_lookup_elem(&domain_freq_map, &hash);
    if (stat) {
        stat->query_count += 1;
        stat->total_bytes += (data_end - (void *)qname);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";