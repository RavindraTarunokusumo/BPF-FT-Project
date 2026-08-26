#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} proto_counters SEC(".maps");

SEC("xdp")
int xdp_count_proto(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 3; // Other
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) <= data_end) {
            if (ip->protocol == IPPROTO_TCP)
                key = 0;
            else if (ip->protocol == IPPROTO_UDP)
                key = 1;
            else if (ip->protocol == IPPROTO_ICMP)
                key = 2;
        }
    }

    __u64 *val = bpf_map_lookup_elem(&proto_counters, &key);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
