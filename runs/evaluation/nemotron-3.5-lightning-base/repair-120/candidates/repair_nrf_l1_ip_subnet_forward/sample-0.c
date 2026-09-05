#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    /* Verify Ethernet header fits within the packet */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    /* Verify IPv4 header fits within the packet before reading daddr */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Match destination IP in 10.0.0.0/8 (0x0A000000) */
    if ((ip->daddr & bpf_htonl(0xFF000000)) == bpf_htonl(0x0A000000))
        return bpf_redirect(3, 0);

    /* Pass non-matching and non-IP traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
