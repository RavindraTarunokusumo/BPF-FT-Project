#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct domain_stat {
    __u64 query_count;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Domain hash
    __type(value, struct domain_stat);
    __uint(max_entries, 1024);
} domain_freq_map SEC(".maps");

SEC("xdp")
int xdp_dns_domain_tracker(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    void *dns_start = (void *)(udp + 1);
    if (dns_start + 12 > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(*(__be16 *)(dns_start + 2));
    if (flags & 0x8000) // Response
        return XDP_PASS;

    __u8 *ptr = dns_start + 12;
    __u32 domain_hash = 0x811c9dc5; // FNV-1a 32-bit offset basis

    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (ptr + 1 > data_end)
            return XDP_PASS;
        __u8 len = *ptr;
        if (len == 0)
            break;
        if (len > 63)
            return XDP_PASS;
        ptr += 1;
        if (ptr + 1 > data_end)
            return XDP_PASS;
        domain_hash = (domain_hash ^ (*ptr)) * 0x01000193;
        ptr += len;
    }

    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
    struct domain_stat *st = bpf_map_lookup_elem(&domain_freq_map, &domain_hash);
    if (!st) {
        struct domain_stat new_st = { .query_count = 1, .total_bytes = pkt_len };
        bpf_map_update_elem(&domain_freq_map, &domain_hash, &new_st, BPF_ANY);
    } else {
        st->query_count += 1;
        st->total_bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
