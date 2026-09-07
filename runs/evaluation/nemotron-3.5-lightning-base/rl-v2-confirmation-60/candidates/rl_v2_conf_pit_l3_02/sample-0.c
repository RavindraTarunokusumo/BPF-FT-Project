#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Map definition: LRU Hash map with __u32 key and struct flow_timing value */
struct flow_timing {
    __u64 first_seen;
    __u64 last_seen;
};

struct bpf_map *flow_time_02 __attribute__((section("maps")));

struct bpf_map *flow_time_02 = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct flow_timing),
    .max_entries = 65536,
};

/* XDP entry point */
SEC("xdp")
int xdp_prog_02(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic (optional, but safe) */
    if (ip->version != 4)
        return XDP_PASS;

    /* Get current timestamp */
    __u64 now = bpf_ktime_get_ns();

    /* Use destination IP as key (__u32) */
    __u32 key = ip->daddr;

    /* Lookup existing flow timing */
    struct flow_timing *timing;
    timing = bpf_map_lookup_elem(flow_time_02, &key, &timing);
    if (!timing) {
        /* First time seeing this host: allocate and initialize */
        struct flow_timing new_timing = {
            .first_seen = now,
            .last_seen  = now,
        };
        bpf_map_update_elem(flow_time_02, &key, &new_timing, BPF_ANY);
    } else {
        /* Update last_seen timestamp */
        timing->last_seen = now;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
