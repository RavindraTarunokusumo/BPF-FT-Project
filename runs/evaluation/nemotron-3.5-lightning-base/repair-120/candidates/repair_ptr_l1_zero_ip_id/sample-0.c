#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    /* Check Ethernet frame bounds */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    /* Check IPv4 header bounds */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Zero the 16-bit IPv4 ID field */
    ip->id = 0;

    /* Recalculate the IPv4 header checksum over the updated header */
    ip->check = bpf_csum_diff(ip->check, 0, sizeof(struct iphdr), 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
