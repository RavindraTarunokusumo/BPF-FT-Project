#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* XDP entry point */
SEC("xdp")
int xdp_tcp23_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Verify Ethernet bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Verify Ethernet protocol is IPv4 (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify IPv4 bounds and parse header */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 4. Verify IP protocol is TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 5. Parse variable IHL safely.
       ip->ihl is in 4-byte units. Multiply by 4 to get byte offset.
       Ensure the TCP header starts within the packet bounds. */
    unsigned int ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip) || data + sizeof(*eth) + ihl > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = data + sizeof(*eth) + ihl;
    if (data + sizeof(*eth) + ihl + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 6. Check if destination port is 23 (Telnet).
       Use bpf_ntohs to convert network byte order to host byte order. */
    if (bpf_ntohs(tcp->dest) == 23) {
        return XDP_DROP;
    }

    /* 7. Pass all other traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
