#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

/* 
 * BPF_MAP_TYPE_HASH map 'mac_ip_auth_map'
 * Key: __u32 (IP address - source IP)
 * Value: unsigned char[6] (MAC address - expected source MAC)
 */
SEC("xdp")
int xdp_mac_ip_auth(struct xdp_md *ctx)
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

    /* Only process IPv4 packets (IPPROTO_IP = 0) */
    if (ip->protocol != IPPROTO_IP)
        return XDP_PASS;

    /* Lookup source IP in the authentication map */
    __u32 key = ip->saddr;
    unsigned char expected_mac[6];

    /* BPF_MAP_TYPE_HASH lookup: returns pointer to value or NULL */
    unsigned char *mac = bpf_map_lookup_elem(
        mac_ip_auth_map, &key, expected_mac);

    if (mac) {
        /* Packet is registered in the map - enforce anti-spoofing */
        /* Compare actual source MAC with expected MAC from map */
        if (memcmp(eth->h_source, mac, ETH_ALEN) != 0) {
            /* Source MAC does not match registered MAC -> drop */
            return XDP_DROP;
        }
        /* Source MAC matches -> allow packet */
        return XDP_PASS;
    }

    /* IP not registered in map -> pass packet */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
