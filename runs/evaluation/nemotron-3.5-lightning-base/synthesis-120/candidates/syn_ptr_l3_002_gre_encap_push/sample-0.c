/* XDP GRE Tunnel Encapsulation Program
 * Task: syn_ptr_l3_002_gre_encap_push
 * Category: protocol_transformation
 * Difficulty: level_3
 *
 * Encapsulates incoming raw IPv4 packets into a GRE tunnel.
 * Outer IPv4: protocol 47, src 192.168.1.1, dst 192.168.1.254
 * GRE proto: 0x0800
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* GRE header definition (4 bytes without key) */
struct grehdr {
    __be16	flags;
    __be16	protocol;
};

/* Ethernet header for bounds checking */
struct eth_hdr {
    unsigned char	h_dest[ETH_ALEN];
    unsigned char	h_source[ETH_ALEN];
    __be16		h_proto;
};

SEC("xdp")
int xdp_gre_encap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct grehdr *gre;
    struct iphdr *outer_ip;
    
    /* Validate minimum Ethernet frame size */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    eth = data;
    
    /* Validate Ethernet type is IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    /* Validate IPv4 header bounds */
    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    /* Verify IPv4 IHL is at least 5 (20 bytes) */
    if (ip->ihl < 5)
        return XDP_PASS;
    
    /* Validate IPv4 total length fits within packet */
    if ((void *)(ip + ip->ihl) > data_end)
        return XDP_PASS;
    
    /* Call bpf_xdp_adjust_head to expand packet head by 24 bytes.
     * This prepends 24 bytes for the outer GRE + IPv4 headers.
     * Returns negative error code on failure. */
    if (bpf_xdp_adjust_head(ctx, -24))
        return XDP_PASS;
    
    /* After adjustment, data pointer moves back by 24 bytes.
     * Recalculate pointers relative to new data start. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    
    /* Re-validate Ethernet header after adjustment */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    /* Re-validate IPv4 header after adjustment */
    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->ihl < 5)
        return XDP_PASS;
    if ((void *)(ip + ip->ihl) > data_end)
        return XDP_PASS;
    
    /* Set up outer IPv4 header at the beginning of the adjusted packet.
     * Outer IPv4 header is 20 bytes (5 * 4).
     * Total expansion: 20 (outer IPv4) + 4 (GRE) = 24 bytes. */
    outer_ip = data;
    
    /* Populate outer IPv4 header */
    outer_ip->version = 4;
    outer_ip->ihl = 5;
    outer_ip->tos = 0;
    outer_ip->tot_len = bpf_htons(ip->tot_len + 24); /* Include GRE header */
    outer_ip->id = ip->id;
    outer_ip->frag_off = 0;
    outer_ip->ttl = 64;
    outer_ip->protocol = IPPROTO_GRE; /* Protocol 47 */
    outer_ip->saddr = bpf_htonl(192168001); /* 192.168.1.1 */
    outer_ip->daddr = bpf_htonl(192168254); /* 192.168.1.254 */
    outer_ip->check = 0; /* Will compute checksum */
    outer_ip->source = 0; /* Initialize to 0 for checksum */
    outer_ip->dest = 0;
    
    /* Compute outer IPv4 checksum using bpf helper */
    outer_ip->check = bpf_csum_diff(0, 0, 0, 0, &outer_ip->source);
    /* Note: bpf_csum_diff with zero arguments computes pseudo-header checksum.
     * For complete IPv4 checksum computation, we need to sum all 16-bit words.
     * The following computes the IPv4 header checksum properly: */
    
    /* Sum all 16-bit words of the outer IPv4 header (excluding the checksum field itself) */
    {
        __sum16 csum = 0;
        int i;
        __be16 *ptr = (__be16 *)outer_ip;
        
        /* Skip the checksum field (offset 10, 2 words) */
        for (i = 0; i < 10; i++)
            csum += *ptr++;
        
        /* Fold carry */
        csum = (csum & 0xffff) + (csum >> 16);
        csum += (csum >> 16);
        
        outer_ip->check = ~csum;
    }
    
    /* Set up GRE header immediately after outer IPv4 header (20 bytes offset) */
    gre = (struct grehdr *)(outer_ip + 1);
    
    /* Populate GRE header */
    gre->flags = 0; /* No flags set */
    gre->protocol = bpf_htons(0x0800); /* IPv4 protocol */
    
    /* The inner IPv4 packet now starts after the 24-byte encapsulation header.
     * No modification needed to the inner packet as bpf_xdp_adjust_head
     * just expanded the headroom. */
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
