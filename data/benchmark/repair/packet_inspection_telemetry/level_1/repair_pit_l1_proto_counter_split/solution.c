#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} proto_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 2; // other

    if ((void *)(eth + 1) <= data_end) {
        __u16 h_proto = bpf_ntohs(eth->h_proto);
        switch (h_proto) {
            case ETH_P_IP:
                slot = 0;
                break;
            case ETH_P_IPV6:
                slot = 1;
                break;
            default:
                slot = 2;
                break;
        }
    }

    __u64 *cnt = bpf_map_lookup_elem(&proto_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
