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
    __uint(max_entries, 4);
} proto_matrix SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 3; // non-IPv4

    if ((void *)(eth + 1) <= data_end) {
        if (eth->h_proto == bpf_htons(ETH_P_IP)) {
            struct iphdr *ip = (void *)(eth + 1);
            if ((void *)(ip + 1) <= data_end) {
                if (ip->protocol == IPPROTO_TCP)
                    slot = 0;
                else if (ip->protocol == IPPROTO_UDP)
                    slot = 1;
                else
                    slot = 2;
            }
        }
    }

    __u64 *cnt = bpf_map_lookup_elem(&proto_matrix, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
