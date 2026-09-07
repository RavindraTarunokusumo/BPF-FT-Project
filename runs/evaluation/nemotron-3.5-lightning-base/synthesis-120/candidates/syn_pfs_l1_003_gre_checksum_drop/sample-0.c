#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/gre.h>
#include <linux/udp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_gre_checksum_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 protocol (0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Verify ip->protocol == 47 (GRE) */
    if (ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* 4. Validate GRE header bounds (struct grehdr) */
    struct grehdr *gre = (struct grehdr *)(ip + 1);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*gre) > data_end)
        return XDP_PASS;

    /* 5. Extract 16-bit flags and check Checksum Present bit (0x8000) */
    __u16 flags = gre->flags;
    if (flags & 0x8000) {
        /* Checksum Present bit is set -> drop */
        return XDP_DROP;
    }

    /* 6. Pass GRE packets without the checksum bit */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
