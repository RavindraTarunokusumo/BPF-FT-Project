#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Route table map definition */
struct route_entry {
    __u32 prefixlen;
    __u32 data; /* gateway MAC address encoded */
};

BPF_LPM_TRIE_DECLARE(dev_route_table_4, 8); /* 8 bits prefix length max for IPv4 */

/* LPM key structure for IPv4 destination lookup */
struct route_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

/* Default gateway MAC: 52:54:00:00:00:fe */
static const __u64 DEFAULT_GW_MAC = 0xfe5452000052ULL;

/* XDP program entry point */
SEC("xdp")
int xdp_route_table_04(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process packets with a valid destination address */
    if (!ip->daddr)
        return XDP_PASS;

    /* Prepare LPM key */
    struct route_lpm_key key = {
        .prefixlen = 32,
        .data = ip->daddr,
    };

    /* Lookup route in the LPM trie map */
    struct route_entry *entry;
    int hit = bpf_lpm_trie_lookup(&dev_route_table_4, &key, sizeof(key), &entry, 0);

    __u64 gw_mac;

    if (hit) {
        /* Route hit: rewrite destination MAC to route gateway MAC */
        gw_mac = entry->data;
    } else {
        /* Route miss: rewrite to default gateway MAC */
        gw_mac = DEFAULT_GW_MAC;
    }

    /* Rewrite Ethernet destination MAC address */
    bpf_eth_store_addr(eth->h_dest, &gw_mac);

    /* Forward the packet via XDP_TX */
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
