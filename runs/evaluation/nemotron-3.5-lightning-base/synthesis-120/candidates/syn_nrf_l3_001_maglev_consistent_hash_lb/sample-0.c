/* XDP Maglev Consistent Hashing Load Balancer
 * Category: network_routing_forwarding
 * Difficulty: level_3
 *
 * Extracts 5-tuple (src/dst IP, src/dst port, protocol) from IPv4 TCP/UDP packets,
 * computes a 32-bit FNV-1a flow hash, indexes into a fixed Maglev lookup table of size 257,
 * and redirects traffic to one of 4 backends (ifindex base = 100).
 *
 * For non-TCP/UDP traffic, the program returns XDP_PASS.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/ctx.h>
#include <bpf/helpers.h>
#include <bpf/libbpf.h>

#define MAGLEV_TABLE_SIZE 257
#define BACKEND_BASE_IFINDEX 100

/* FNV-1a 32-bit constants */
#define FNV_OFFSET_BASIS 0x811c9dc5
#define FNV_PRIME        0x01000193

/* Maglev lookup table (placeholder - populated by userspace or compiled in) */
static const __u16 maglev_table[MAGLEV_TABLE_SIZE] = {
    [0 ... MAGLEV_TABLE_SIZE - 1] = 0
};

/* FNV-1a 32-bit hash */
static __u32 fnv1a_32(const void *key, int len)
{
    const __u8 *data = key;
    __u32 hash = FNV_OFFSET_BASIS;
    int i;

    for (i = 0; i < len; i++)
        hash = (hash ^ data[i]) * FNV_PRIME;

    return hash;
}

/* Compute 5-tuple flow hash for IPv4 TCP/UDP packets */
static __u32 compute_flow_hash(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    __u16 protocol;
    __u32 hash = 0;
    __u16 src_port = 0, dst_port = 0;

    /* Validate Ethernet frame */
    eth = (struct eth_hdr *)ctx->data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    /* Validate IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    /* Must be IPv4 */
    if (ip->version != 4)
        return 0;

    /* Only process TCP or UDP */
    protocol = ip->protocol;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 0;

    /* Transport layer validation */
    void *transport = (void *)(ip + 1);
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        /* Basic TCP header check - ensure at least source/dest port present */
        if (tcp->source == 0 && tcp->dest == 0)
            return 0;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else { /* IPPROTO_UDP */
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return 0;
        src_port = udp->source;
        dst_port = udp->dest;
    }

    /* Build 5-tuple: proto(1) + src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) = 13 bytes */
    /* Using FNV-1a for good distribution */
    hash = fnv1a_32(&protocol, sizeof(protocol));
    hash = fnv1a_32(&ip->saddr, sizeof(ip->saddr));
    hash = fnv1a_32(&ip->daddr, sizeof(ip->daddr));
    hash = fnv1a_32(&src_port, sizeof(src_port));
    hash = fnv1a_32(&dst_port, sizeof(dst_port));

    return hash;
}

/* XDP program entry point */
SEC("xdp")
int maglev_lb_xdp(struct xdp_md *ctx)
{
    __u32 hash;
    __u16 backend_id;
    __u16 ifindex;

    /* Compute 5-tuple flow hash */
    hash = compute_flow_hash(ctx);

    /* If not TCP/UDP, pass through */
    if (hash == 0)
        return XDP_PASS;

    /* Index into Maglev table: hash % 257 */
    __u16 table_index = hash % MAGLEV_TABLE_SIZE;

    /* Lookup backend ID from Maglev table */
    backend_id = maglev_table[table_index];

    /* Compute redirect ifindex: base(100) + backend_id (modulo 4 for 4 backends) */
    /* Requirement: return bpf_redirect(100 + (hash % 4), 0) */
    /* Using hash % 4 to select backend, then adding base offset */
    ifindex = BACKEND_BASE_IFINDEX + (hash % 4);

    /* Redirect to selected backend */
    return bpf_redirect(ifindex, 0);
}

char _license[] SEC("license") = "GPL";
