#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define CMS_ROWS 4
#define CMS_COLS 256
#define CMS_TOTAL (CMS_ROWS * CMS_COLS)

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CMS_TOTAL);
} cms_sketch_map SEC(".maps");

static __always_inline __u32 hash_row(__u32 fhash, int row) {
    __u32 h = fhash ^ (row * 0x9e3779b9);
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = (h >> 16) ^ h;
    return (row * CMS_COLS) + (h % CMS_COLS);
}

SEC("xdp")
int xdp_cms_heavy_hitters(struct xdp_md *ctx) {
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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    } else {
        return XDP_PASS;
    }

    __u32 flow_hash = ip->saddr ^ ip->daddr ^ ((__u32)src_port << 16 | dst_port) ^ ip->protocol;

    #pragma unroll
    for (int r = 0; r < CMS_ROWS; r++) {
        __u32 idx = hash_row(flow_hash, r);
        __u64 *cnt = bpf_map_lookup_elem(&cms_sketch_map, &idx);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
