#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int xdp_inspect_ip_options(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic (ETH_P_IP = 0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Drop IPv4 datagrams with IP options (IHL > 5) */
    if (ip->ihl > 5) {
        /* IHL is in 32-bit words; value 5 means 20 bytes (no options).
         * Values > 5 indicate the presence of IP options. */
        return XDP_DROP;
    }

    /* Standard IHL (5) or non-option IPv4: pass through */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
