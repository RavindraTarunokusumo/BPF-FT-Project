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
    
    // Check Ethernet bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check for IPv4 protocol
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    // Check IPv4 bounds
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Drop packets with TTL <= 1
    if (ip->ttl <= 1)
        return XDP_DROP;

    // Decrement TTL
    ip->ttl -= 1;

    // Update IPv4 checksum
    // Decrementing a byte by 1 requires subtracting 1 from the checksum.
    // Using signed subtraction handles the underflow/carry correctly.
    ip->check -= 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
