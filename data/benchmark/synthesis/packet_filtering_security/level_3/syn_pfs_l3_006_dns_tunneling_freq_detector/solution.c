#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_DNS_BYTES_PER_SEC 500ULL
#define NS_PER_SEC            1000000000ULL

struct dns_client_stat {
    __u64 window_start_ns;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct dns_client_stat);
    __uint(max_entries, 1024);
} dns_tunnel_map SEC(".maps");

SEC("xdp")
int xdp_dns_tunnel_detector(struct xdp_md *ctx) {
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
    if (flags & 0x8000) // QR bit == 1 (Response)
        return XDP_PASS;

    __u64 query_len = (__u64)((void *)data_end - dns_start);
    __be32 client_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct dns_client_stat *st = bpf_map_lookup_elem(&dns_tunnel_map, &client_ip);
    if (!st) {
        struct dns_client_stat new_st = { .window_start_ns = now, .total_bytes = query_len };
        bpf_map_update_elem(&dns_tunnel_map, &client_ip, &new_st, BPF_ANY);
        if (query_len > MAX_DNS_BYTES_PER_SEC)
            return XDP_DROP;
        return XDP_PASS;
    }

    if (now - st->window_start_ns >= NS_PER_SEC) {
        st->window_start_ns = now;
        st->total_bytes = query_len;
        if (query_len > MAX_DNS_BYTES_PER_SEC)
            return XDP_DROP;
        return XDP_PASS;
    }

    st->total_bytes += query_len;
    if (st->total_bytes > MAX_DNS_BYTES_PER_SEC)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
