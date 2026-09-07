#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int xdp_ipsec_transport_drop(struct xdp_md *ctx)
{
    void *data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;

    /* 1. Retrieve the end of the packet data buffer */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* 2. Verify Ethernet header bounds */
    if (data + sizeof(struct eth_hdr) > data_end)
        return XDP_PASS;

    eth = data;

    /* 3. Check for IPv4 EtherType (0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 4. Verify IPv4 header bounds */
    if (data + sizeof(struct eth_hdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);

    /* 5. Inspect IP protocol field */
    if (ip->protocol == IPPROTO_ESP) { /* 50 */
        /* Drop Encapsulating Security Payload IPsec transport frames */
        return XDP_DROP;
    }

    /* 6. Forward all other packets */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
