#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* 
 * BPF_MAP_TYPE_HASH map 'port_quota_map' 
 * Key: __u16 (destination port)
 * Value: __u64 (packet counter)
 */
SEC("xdp")
int xdp_port_quota_inspector(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process IPv4 TCP traffic */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Verify TCP header bounds */
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* Get destination port (__u16) */
    __u16 dest_port = tcp->dest;

    /* Define map name and lookup/update parameters */
    __u32 key = dest_port;
    __u64 *val, zero = 0, increment = 1;

    /* Lookup or update the counter atomically */
    val = bpf_map_lookup_elem(port_quota_map, &key, &zero, BPF_ANY);
    if (val == NULL) {
        /* First packet for this port: initialize with 1 */
        val = &zero;
        bpf_map_update_elem(port_quota_map, &key, val, BPF_ANY);
    }

    /* Atomically increment the packet counter */
    (*val)++;

    /* Drop if quota exceeded (>= 1000 packets) */
    if (*val >= 1000)
        return XDP_DROP;

    /* Pass all other packets */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
