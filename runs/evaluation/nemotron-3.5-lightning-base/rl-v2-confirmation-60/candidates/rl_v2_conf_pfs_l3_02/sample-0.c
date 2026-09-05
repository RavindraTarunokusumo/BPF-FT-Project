#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

/* Define the IP pair structure for map key */
struct ip_pair {
    __be32 saddr; /* source IP address */
    __be32 daddr; /* destination IP address */
};

/* Define the LRU hash map */
struct bpf_map_def __attribute__((section("maps"))) ip_pair_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct ip_pair),
    .value_size = sizeof(__u64),
    .max_entries = 1024,
};

/* XDP program entry point */
SEC("xdp")
int xdp_restrict_sessions(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Build the IP pair key */
    struct ip_pair key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
    };

    /* Lookup or create the counter in the map */
    __u64 *val, zero = 0;
    int ret;

    val = bpf_map_lookup_elem(ip_pair_map, &key, &zero, BPF_ANY);
    if (val) {
        /* Counter exists, increment it */
        (*val)++;
    } else {
        /* Counter does not exist, initialize to 1 */
        __u64 init_val = 1;
        ret = bpf_map_update_elem(ip_pair_map, &key, &init_val, BPF_ANY);
        if (ret)
            return XDP_PASS;
        val = &init_val;
    }

    /* Drop if packet count exceeds 50 */
    if (*val > 50)
        return XDP_DROP;

    /* Forward all other packets */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
