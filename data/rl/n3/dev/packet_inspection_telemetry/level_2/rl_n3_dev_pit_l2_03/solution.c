#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} dst_bytes_03 SEC(".maps");

SEC("xdp")
int xdp_bytes_dst_3(struct xdp_md *ctx) {
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

    __u32 dst = ip->daddr;
    __u64 pkt_bytes = bpf_ntohs(ip->tot_len);

    __u64 *val = bpf_map_lookup_elem(&dst_bytes_03, &dst);
    if (val) {
        __sync_fetch_and_add(val, pkt_bytes);
    } else {
        bpf_map_update_elem(&dst_bytes_03, &dst, &pkt_bytes, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
