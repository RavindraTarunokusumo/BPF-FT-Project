#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Map definition */
struct flow_timing {
    __u64 first_seen;
    __u64 last_seen;
};

struct bpf_map_def __attribute__((section("maps"))) flow_time_03 = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct flow_timing),
    .max_entries = 65536,
};

/* XDP entry point */
SEC("xdp")
int xdp_flow_time_03(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic */
    if (ip->version != 4)
        return XDP_PASS;

    /* Key is the source IP address */
    __u32 key = ip->saddr;

    /* Query or update the map entry */
    struct flow_timing *t = bpf_map_lookup_elem(&flow_time_03, &key);
    if (!t) {
        /* First time seeing this source IP: allocate and set both timestamps */
        struct flow_timing new = {
            .first_seen = bpf_ktime_get_ns(),
            .last_seen  = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_time_03, &key, &new, BPF_ANY);
    } else {
        /* Update last_seen on every encounter */
        t->last_seen = bpf_ktime_get_ns();
        /* first_seen is already set from the initial insertion */
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
