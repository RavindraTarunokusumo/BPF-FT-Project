#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* XDP program entry point */
SEC("xdp")
int block_syn_fin_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 protocol and header bounds */
    /* Check Ethernet type == IPv4 (0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Confirm protocol is IPPROTO_TCP and validate variable IPv4 header length */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Validate IPv4 IHL: minimum 5 32-bit words (20 bytes), shift left by 2 */
    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > sizeof(*ip))
        return XDP_PASS;

    if (data + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS;

    /* 4. Verify TCP header bounds */
    struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*eth) + ip_hdr_len);
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 5. Drop packet if both SYN and FIN flags are set simultaneously */
    if (tcp->syn && tcp->fin) {
        return XDP_DROP;
    }

    /* 6. Forward all other packets */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
