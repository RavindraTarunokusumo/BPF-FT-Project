#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

/* 
 * BPF_MAP_TYPE_HASH map 'blocked_knock_map'
 * Key: __u32 (source IP address)
 * Max entries: 512
 */
SEC("xdp")
int xdp_blocked_knock(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 protocol and header bounds */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets with source address */
    __u32 src_ip = ip->saddr;

    /* Lookup source IP in blocked_knock_map */
    if (bpf_map_lookup_elem(BPF_MAP_TYPE_HASH, &blocked_knock_map, &src_ip, sizeof(src_ip)) == 0) {
        /* Key found -> host is blocked */
        return XDP_DROP;
    }

    /* Key not found -> allow packet */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
