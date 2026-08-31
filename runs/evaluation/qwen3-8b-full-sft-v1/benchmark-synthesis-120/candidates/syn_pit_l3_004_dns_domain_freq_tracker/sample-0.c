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
} domain_freq_map_4 SEC(".maps");

static __always_inline __u32
fnv1a_hash(const void *data, __u32 len) {
    __u32 hash = 0x811C9DC5;
    const __u8 *p = data;
    while (len--) {
        hash ^= *p++;
        hash *= 0x01000193;
    }
    return hash;
}

SEC("xdp")
int xdp_telemetry_syn_pit_l3_004_dns_domain_freq_tracker(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if (udp_hdr_len > (data_end - (void *)udp))
        return XDP_PASS;

    unsigned char *qname = (void *)(udp + 1);
    if ((void *)qname + 1 > data_end)
        return XDP_PASS;

    __u32 hash = 0;
    while (*qname) {
        if ((void *)(qname + 1) > data_end)
            break;
        hash ^= *qname;
        hash *= 0x01000193;
        qname++;
    }
    if ((void *)qname <= data_end) {
        hash ^= 0;
        hash *= 0x01000193;
    }

    struct domain_stat *stats = bpf_map_lookup_elem(&domain_freq_map_4, &hash);
    if (stats) {
        __sync_fetch_and_add(&stats->query_count, 1);
        __sync_fetch_and_add(&stats->total_bytes, (data_end - (void *)data));
    } else {
        struct domain_stat initial = {
            .query_count = 1,
            .total_bytes = (data_end - (void *)data),
        };
        bpf_map_update_elem(&domain_freq_map_4, &hash, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
