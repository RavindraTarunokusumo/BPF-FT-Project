#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    // Check Ethernet header bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IPv4 header start is right after Ethernet
    struct iphdr *ip = (void *)(eth + 1);
    
    // Check IPv4 header bounds
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Calculate TCP header offset based on IPv4 IHL (Internet Header Length)
    // ihl is in 32-bit words, so multiply by 4 to get bytes
    __u32 ip_len = (__u32)ip->ihl * 4;
    
    // TCP header starts immediately after the IPv4 header
    struct tcphdr *tcp = (void *)ip + ip_len;
    
    // Verifier boundary check: Ensure tcp + 1 is within data_end
    // This prevents out-of-bounds reads when reading tcp->dest
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Check if destination port is 8080
    if (tcp->dest == bpf_htons(8080))
        return bpf_redirect(4, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
