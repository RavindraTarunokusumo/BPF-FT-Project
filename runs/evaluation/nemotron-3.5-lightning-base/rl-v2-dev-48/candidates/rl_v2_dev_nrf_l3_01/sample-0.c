#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

/* Route table map definition */
struct route_entry {
    __u32 prefixlen;
    __u32 data;
};

struct bpf_map_def __attribute__((section("map"))) dev_route_table_1 = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u32),      /* ip->daddr */
    .value_size = sizeof(struct route_entry),
    .max_entries = 256,
    .flags = BPF_F_NO_PREALLOC,
};

/* Default gateway route entry (static initializer) */
static const struct route_entry default_gw = {
    .prefixlen = 32,
    .data = 0xfe00000054525400 /* little-endian: 52:54:00:00:00:fe */
};

/* XDP program entry point */
SEC("xdp")
int xdp_route_ipv4(struct bpf_xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Lookup destination address in the LPM trie route table */
    __u32 daddr = ip->daddr;
    struct route_entry *entry;

    entry = bpf_lpm_lookup(&dev_route_table_1, &daddr, sizeof(daddr), 0);
    if (!entry) {
        /* Route miss: rewrite MAC to default gateway and forward */
        bpf_eth_update_dst_addr(eth, &default_gw.data);
        return XDP_TX;
    }

    /* Route hit: rewrite MAC to route gateway MAC and forward */
    /* The 'data' field of the LPM entry contains the gateway MAC
       in network byte order (6 bytes followed by padding to 4 bytes). */
    bpf_eth_update_dst_addr(eth, &entry->data);
    return XDP_TX;
}

char LICENSE[] __attribute__((section("license"))) = "GPL";
