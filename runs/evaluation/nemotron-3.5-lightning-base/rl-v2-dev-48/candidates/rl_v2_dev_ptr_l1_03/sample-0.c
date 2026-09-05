#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_ttl_decrement(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Decrement TTL if > 1 */
    if (ip->ttl > 1) {
        ip->ttl--;

        /* Recalculate IPv4 header checksum over all 20 bytes */
        /* IP header checksum is stored in network byte order */
        ip->check = 0;
        /* Sum all 16-bit words of the 20-byte header */
        u32 sum = 0;
        u16 *ptr = (u16 *)ip;

        for (int i = 0; i < 10; i++) {
            sum += *ptr++;
        }

        /* Fold 32-bit sum to 16 bits */
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        ip->check = ~sum;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
