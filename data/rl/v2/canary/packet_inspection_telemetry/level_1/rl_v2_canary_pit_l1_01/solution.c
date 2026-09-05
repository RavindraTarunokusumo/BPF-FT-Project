#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} frame_type_map SEC(".maps");

SEC("xdp")
int xdp_count_frames(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 idx = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP))
        idx = 1;
    else if (eth->h_proto == bpf_htons(ETH_P_ARP))
        idx = 2;

    __u64 *counter = bpf_map_lookup_elem(&frame_type_map, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
