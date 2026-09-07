#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    // Check Ethernet bounds before reading MAC
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check multicast MAC bit: eth->h_dest[0] & 0x01
    // This catches both IPv4 multicast (01:00:5E...) and other multicast groups
    if (eth->h_dest[0] & 0x01) {
        // Exclude broadcast ff:ff:ff:ff:ff:ff
        // Broadcast has all bits set, so h_dest[0] is 0xff
        if (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff && 
            eth->h_dest[2] == 0xff && eth->h_dest[3] == 0xff && 
            eth->h_dest[4] == 0xff && eth->h_dest[5] == 0xff)
            return XDP_PASS;
        return XDP_DROP;
    }

    // Handle IPv4 packets
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        
        // Check IPv4 bounds
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        
        // Class D 224.0.0.0/4 check
        // ip->daddr is stored in network byte order. 
        // The first byte (most significant) determines the class.
        // 224.0.0.0/4 means the first 4 bits are 1110 (0xE).
        // We use ip->daddr[0] to safely read the first byte.
        if ((ip->daddr[0] & 0xF0) == 0xE0)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
