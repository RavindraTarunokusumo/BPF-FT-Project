#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    // Check Ethernet frame bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    // Check IPv4 header bounds and respect IHL (Internet Header Length)
    // ip->ihl is in 32-bit words; multiply by 4 to get bytes.
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    // Subnet check for 198.51.100.0/24
    // Network byte order constant: 0xC6336400
    __u32 subnet = bpf_htonl(0xC6336400);
    __u32 mask = bpf_htonl(0xFFFFFF00);
    
    // FIX: Dereference &ip->saddr to get the __u32 value before applying the mask.
    // Original: (&ip->saddr & mask) -> Error: invalid operands ('__be32 *' and '__u32')
    // Corrected: (ip->saddr & mask) -> Compares the scalar IP address against the subnet.
    if ((ip->saddr & mask) == subnet) {
        // Check if this is UDP traffic
        if (ip->protocol == IPPROTO_UDP) {
            // Calculate offset to UDP header immediately after the IP header
            // (ip + ip_len) points to the first byte after the IP header.
            struct udphdr *udp = (void *)(ip + ip_len);
            
            // Verify UDP header fits within the packet bounds
            if ((void *)(udp + 1) <= data_end && udp->dest == bpf_htons(53))
                return XDP_PASS; // Allow DNS traffic
        }
        // Drop traffic from the blocked subnet (non-DNS UDP or other protocols)
        return XDP_DROP;
    }

    // Pass traffic outside the blocked subnet
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
