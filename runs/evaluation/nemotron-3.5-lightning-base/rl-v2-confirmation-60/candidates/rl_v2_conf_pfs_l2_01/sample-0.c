#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_tcp_xmas_scan_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 protocol and header bounds */
    /* Check EtherType == IPv4 (0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Confirm protocol is IPPROTO_TCP and validate IHL */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Safely validate variable IPv4 header length (ihl * 4) */
    /* ihl is in 32-bit words; minimum is 5 (20 bytes) */
    if (ip->ihl < 5)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    if (data + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS;

    /* 4. Verify TCP header bounds */
    struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 5. Drop packet if FIN, PSH, and URG are simultaneously asserted */
    /* Flags are bitfields within tcphdr; check all three bits set */
    if (tcp->fin && tcp->psh && tcp->urg) {
        return XDP_DROP;
    }

    /* 6. Forward all other packets */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
