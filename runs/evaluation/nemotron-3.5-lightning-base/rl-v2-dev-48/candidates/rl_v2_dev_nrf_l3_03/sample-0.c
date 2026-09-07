#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/* 
 * LPM Trie map for route lookup.
 * BPF_F_NO_PREALLOC prevents automatic allocation of the map,
 * requiring explicit bpf_map_create() or userspace setup.
 */
struct bpf_map_def __attribute__((section("map"))) dev_route_table_3 = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = 8,   /* sizeof(struct route_lpm_key) */
    .value_size = 6, /* 6 bytes for MAC address */
    .max_entries = 256,
    .flags = BPF_F_NO_PREALLOC,
};

/*
 * LPM Key structure:
 * - prefixlen: Number of significant bits in the prefix (0-32)
 * - data:    Next hop IP address or index
 */
struct route_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

/* XDP program entry point */
SEC("xdp") int xdp_route_forward(struct xdp_md *ctx)
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

    /* Only process destination IPv4 addresses */
    if (ip->protocol != IPPROTO_ICMP && ip->daddr == 0)
        return XDP_PASS;

    /* Perform LPM trie lookup in dev_route_table_3 */
    struct route_lpm_key key = {
        .prefixlen = 32,
        .data = ip->daddr,
    };

    /* values[0] will contain the gateway MAC address (6 bytes) */
    void *next_hop_mac = bpf_map_lookup_elem(&dev_route_table_3, &key);
    
    /* Default gateway MAC: 52:54:00:00:00:fe */
    static const unsigned char default_gw_mac[6] = {0x52, 0x54, 0x00, 0x00, 0x00, 0xfe};
    unsigned char gw_mac[6];

    if (next_hop_mac) {
        /* Route hit: copy gateway MAC from map value */
        bpf_copy(&gw_mac, next_hop_mac, 6);
    } else {
        /* Route miss: use default gateway MAC */
        bpf_copy(&gw_mac, default_gw_mac, 6);
    }

    /* Rewrite destination MAC address in Ethernet header */
    bpf_eth_rewrite(eth, NULL, gw_mac, NULL);

    /* Forward packet via XDP_TX */
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
