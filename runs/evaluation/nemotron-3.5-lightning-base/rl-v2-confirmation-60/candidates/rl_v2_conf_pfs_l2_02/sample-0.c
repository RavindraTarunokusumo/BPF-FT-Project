#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_tcp_null_scan_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 header and confirm protocol is IPPROTO_TCP */
    /* Check EtherType == htons(ETH_P_IP) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Confirm protocol is TCP and safely validate IPv4 header length */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Validate IPv4 header length: ihl is in 32-bit words, multiply by 4 */
    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || 
        data + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS;

    /* 4. Verify TCP header bounds against data_end */
    struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*eth) + ip_hdr_len);
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 5. Drop packet if TCP control flags byte is zero (Null scan) */
    /* tcphdr->flags is a u16; checking the lower 8 bits for zero */
    if ((tcp->flags & 0xFF) == 0)
        return XDP_DROP;

    /* 6. Forward all other packets */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
