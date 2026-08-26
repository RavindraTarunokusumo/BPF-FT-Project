#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8);
    __type(value, __u8);
    __uint(max_entries, 32);
} proto_denylist SEC(".maps");

SEC("xdp")
int xdp_map_proto(struct xdp_md *ctx) {
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

    __u8 proto = ip->protocol;
    __u8 *val = bpf_map_lookup_elem(&proto_denylist, &proto);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
