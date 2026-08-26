#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") protocol_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

SEC("xdp")
int xdp_program(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data + ETH_HLEN > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Non-IPv4 packet
        __u32 key = 3;
        __u64 *count = bpf_map_lookup_elem(&protocol_counters, &key);
        if (count)
            *count += 1;
        return XDP_PASS;
    }

    // Check IPv4 header bounds
    if (data + ETH_HLEN + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + ETH_HLEN;
    __u32 slot;
    switch (ip->protocol) {
        case IPPROTO_TCP:
            slot = 0;
            break;
        case IPPROTO_UDP:
            slot = 1;
            break;
        default:
            slot = 2;
            break;
    }

    __u32 key = slot;
    __u64 *count = bpf_map_lookup_elem(&protocol_counters, &key);
    if (count)
        *count += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
