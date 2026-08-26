#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} protocol_counts SEC(".maps");

SEC("xdp")
int telemetry_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 key = 3;

    if ((void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        key = 2;
        if ((void *)(ip + 1) <= data_end) {
            if (ip->protocol == IPPROTO_TCP)
                key = 0;
            else if (ip->protocol == IPPROTO_UDP)
                key = 1;
        }
    }

    __u64 *counter = bpf_map_lookup_elem(&protocol_counts, &key);
    if (counter)
        (*counter)++;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
