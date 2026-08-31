#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} dscp_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    // Behavioral bug: masked 0xFC without shifting right by 2
    __u32 dscp = (ip->tos & 0xFC) & 63;

    __u64 *cnt = bpf_map_lookup_elem(&dscp_stats, &dscp);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
