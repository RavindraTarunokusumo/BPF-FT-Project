#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    // Check that the Ethernet header fits within the packet bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if the EtherType matches ARP (0x0806)
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        __u8 tmp[ETH_ALEN];
        // Swap the source and destination MAC addresses
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        
        // Transmit the reflected ARP request frame back out the interface
        return XDP_TX;
    }

    // Pass non-ARP traffic through the network stack
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
