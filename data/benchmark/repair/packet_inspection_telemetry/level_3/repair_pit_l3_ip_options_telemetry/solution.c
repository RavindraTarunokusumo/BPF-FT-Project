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
    __uint(max_entries, 256);
} options_stats SEC(".maps");

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

    if (ip->ihl > 5) {
        char *opt = (char *)(ip + 1);
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if ((void *)(opt + i + 1) <= data_end && i < ((ip->ihl - 5) * 4)) {
                __u32 opt_type = (__u8)opt[i];
                __u64 *cnt = bpf_map_lookup_elem(&options_stats, &opt_type);
                if (cnt)
                    *cnt += 1;
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
