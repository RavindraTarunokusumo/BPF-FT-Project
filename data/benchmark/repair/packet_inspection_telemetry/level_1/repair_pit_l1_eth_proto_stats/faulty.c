#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} eth_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 1;

    if ((void *)(eth + 1) <= data_end) {
        // Compilation error: ETH_P_IP undeclared without linux/if_ether.h
        if (eth->h_proto == bpf_htons(ETH_P_IP))
            slot = 0;
    }

    __u64 *cnt = bpf_map_lookup_elem(&eth_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
