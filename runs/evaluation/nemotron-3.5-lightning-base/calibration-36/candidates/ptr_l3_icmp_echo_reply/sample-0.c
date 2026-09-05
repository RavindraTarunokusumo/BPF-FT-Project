/* XDP ICMP Echo Request -> Echo Reply Responder
 * Category: protocol_transformation
 * Difficulty: level_3
 *
 * Converts valid IPv4 ICMP Echo Requests (type 8, code 0) into
 * ICMP Echo Replies in-place, swapping MACs, IPs, and updating
 * the checksum. All other traffic is passed through.
 *
 * Compilation: clang -target bpf -O2 -c icmp_echo_responder.c -o icmp_echo_responder.o
 * License: GPL-2.0
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/ctx/sk_buff.h>

SEC("xdp")
int icmp_echo_responder(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Verify Ethernet frame bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify IPv4 header bounds */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 4. Verify IPv4 protocol is ICMP */
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    /* 5. Parse variable IHL and verify ICMP header bounds.
       ip->ihl is in 4-byte units; actual header length = ihl * 4. */
    void *icmp_start = (void *)(ip + 1);
    /* ip header may be shorter than sizeof(*ip) if IHL < 5, but kernel
       usually enforces minimum IHL of 5. We guard against overflow. */
    if (ip->ihl < 5 || (void *)(icmp_start + (ip->ihl * 4)) > data_end)
        return XDP_PASS;

    /* 6. Point to ICMP header within the IP payload */
    struct icmphdr *icmp = icmp_start;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    /* 7. Check for ICMP Echo Request (type 8, code 0) */
    if (icmp->type != 8 || icmp->code != 0)
        return XDP_PASS;

    /* -------------------------------------------------------------
     * 8. Perform in-place transformation
     * -------------------------------------------------------------
     * (1) Swap Ethernet MAC addresses
     */
    {
        unsigned char tmp[ETH_ALEN];
        bpf_probe_read_kernel(tmp, ETH_ALEN, eth->h_source);
        bpf_probe_read_kernel(eth->h_source, ETH_ALEN, eth->h_dest);
        bpf_probe_read_kernel(eth->h_dest, ETH_ALEN, tmp);
    }

    /* (2) Swap IPv4 source and destination addresses */
    {
        __be32 tmp = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp;
    }

    /* (3) Change ICMP type from 8 (Echo Request) to 0 (Echo Reply) */
    icmp->type = 0; /* code remains 0 */

    /* (4) Update ICMP checksum.
       The ICMP checksum field is at icmp->check.
       We add 0x0800 (type change 8->0, code unchanged) with carry wrap. */
    {
        __be16 *csum = &icmp->check;
        __u32 new_csum = bpf_ntohl(*csum) + 0x0800;
        /* Carry wrap: fold upper 16 bits into lower 16 bits */
        new_csum = (new_csum & 0xFFFF) + (new_csum >> 16);
        /* One's complement */
        *csum = bpf_htons(~new_csum);
    }

    /* 9. Transmit the reply immediately */
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
