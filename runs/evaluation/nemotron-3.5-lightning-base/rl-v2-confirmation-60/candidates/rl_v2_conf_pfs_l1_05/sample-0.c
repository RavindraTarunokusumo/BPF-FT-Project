#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int xdp_drop_sctp_multihomed(struct xdp_md *ctx)
{
    void *data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;

    /* 1. Retrieve the end of the mapped data buffer */
    data = (void *)(long)ctx->data_end;
    data_end = (void *)(long)ctx->data;

    /* 2. Verify Ethernet header bounds */
    if (data + sizeof(struct eth_hdr) > data_end)
        return XDP_PASS;

    eth = data;

    /* 3. Verify IPv4 payload bounds and inspect IP header */
    /* Check that there is enough room for the IPv4 header after Ethernet */
    if (data + sizeof(struct eth_hdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);

    /* 4. Verify IPv4 header bounds (ip->ihl * 4 gives header length) */
    /* The IPv4 header length in 32-bit words is stored in the first nibble of version/IHL */
    if (ip + ip->ihl > data_end)
        return XDP_PASS;

    /* 5. Drop SCTP multihomed traffic (IP protocol 132) */
    if (ip->protocol == 132)
        return XDP_DROP;

    /* 6. Forward all other packets */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
