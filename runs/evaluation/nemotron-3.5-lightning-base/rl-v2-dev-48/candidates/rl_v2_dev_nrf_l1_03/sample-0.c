#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>

/* Helper to calculate IPv4 header checksum */
static __sum16 ip_checksum(void *addr, int len)
{
    __sum32 sum = 0;
    unsigned short *ptr = addr;
    int i;

    for (i = 0; i < len / 2; i++)
        sum += *ptr++;

    if (len % 2)
        sum += *(unsigned char *)ptr;

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

SEC("xdp")
int xdp_forward_decrement_ttl(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;

    /* 1. Verify Ethernet header bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Confirm eth->h_proto == ETH_P_IP */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify IPv4 header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);

    /* 4. Drop packet if TTL <= 1 */
    if (ip->ttl <= 1)
        return XDP_DROP;

    /* 5. Decrement TTL */
    ip->ttl--;

    /* 6. Recalculate IPv4 header checksum */
    /* ip->check is the 16-bit one's complement sum of the header */
    ip->check = ip_checksum(ip, sizeof(struct iphdr));

    /* 7. Forward packet */
    return XDP_TX;
}

char LICENSE[] = "GPL";
