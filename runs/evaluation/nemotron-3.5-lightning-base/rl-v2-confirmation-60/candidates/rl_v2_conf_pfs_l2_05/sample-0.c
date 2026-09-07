#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_rst_ack_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 header and protocol */
    /* Check Ethernet type == IPv4 (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Confirm protocol is IPPROTO_TCP and validate variable IPv4 header length */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Validate IPv4 header length: ihl is in 32-bit words, multiply by 4 */
    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip) || data + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS;

    /* 4. Verify TCP header bounds */
    struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*eth) + ip_hdr_len);
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 5. Drop packet if both RST and ACK flags are set */
    if (tcp->rst && tcp->ack)
        return XDP_DROP;

    /* 6. Forward all other packets */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
