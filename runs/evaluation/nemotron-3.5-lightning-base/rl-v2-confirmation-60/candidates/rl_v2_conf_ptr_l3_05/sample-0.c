#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP entry point */
SEC("xdp")
int xdp_decapsulate_gre(void *ctx)
{
    void *data = (void *)ctx;
    void *data_end = data + sizeof(struct ethhdr);
    struct ethhdr *eth = data;
    struct iphdr *outer_ip;
    u32 outer_len;
    void *nh;

    /* 1. Verify Ethernet header bounds */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* 2. Check for IPv4 protocol (0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify outer IPv4 header fits */
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    outer_ip = data + sizeof(struct ethhdr);

    /* 4. Check if outer protocol is GRE (47) */
    if (outer_ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* 5. Calculate total encapsulation length:
       outer_ip->ihl is in 4-byte units, so ihl * 4 gives outer IP header size.
       Add 4 bytes for the GRE protocol header. */
    outer_len = (outer_ip->ihl * 4) + 4;

    /* 6. Verify total encapsulation fits within the packet */
    if (data + sizeof(struct ethhdr) + outer_len > data_end)
        return XDP_PASS;

    /* 7. Back up the original Ethernet header */
    nh = bpf_xdp_adjust_head(ctx, -(long)outer_len);
    if (!nh)
        return XDP_PASS;

    /* 8. Restore Ethernet header with ETH_P_IP */
    eth = nh;
    eth->h_proto = htons(ETH_P_IP);

    /* 9. Return XDP_PASS unconditionally */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
