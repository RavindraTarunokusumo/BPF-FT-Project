#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} routing_table SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_ABORTED;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_ABORTED;

    __u32 dst = ip->daddr;
    __u32 *egress = bpf_map_lookup_elem(&routing_table, &dst);
    if (egress)
        return bpf_redirect(*egress, 0);

    // Behavioral bug: returned XDP_PASS instead of XDP_ABORTED on route miss
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
