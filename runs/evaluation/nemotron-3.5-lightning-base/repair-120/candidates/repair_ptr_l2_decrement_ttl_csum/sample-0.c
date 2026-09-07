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

    // Update IPv4 header checksum.
    // bpf_csum_update adds a 16-bit value to the checksum.
    // We add 0x0100 to decrement the TTL value (network byte order).
    ip->check = bpf_csum_update(&ip->check, 0x0100, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
