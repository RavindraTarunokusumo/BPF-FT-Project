#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_npt_drop_unauth(void *ctx)
{
    void *data = (void *)(long)ctx;
    void *data_end = data + ctx_size; /* ctx_size is provided by the verifier */

    /* 1. Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 protocol and header bounds */
    /* Check EtherType == htons(ETH_P_IP) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 3. Confirm protocol is IPPROTO_UDP and validate IPv4 header length */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Safely validate variable IPv4 header length: ihl is in 32-bit words */
    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > data_end - (void *)ip)
        return XDP_PASS;

    /* 4. Verify UDP header bounds against data_end */
    void *udp_start = (void *)ip + ip_hdr_len;
    struct udphdr *udp = udp_start;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* 5. Drop packet with XDP_DROP if UDP destination port equals 123 */
    if (udp->dest == htons(123))
        return XDP_DROP;

    /* 6. Return XDP_PASS for non-matching or malformed traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
