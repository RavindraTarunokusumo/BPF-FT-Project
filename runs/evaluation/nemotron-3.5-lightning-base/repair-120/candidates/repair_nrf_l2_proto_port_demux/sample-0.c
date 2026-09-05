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
    
    // Check Ethernet bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check for IPv4 protocol
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    // Check IPv4 header bounds
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Redirect TCP traffic to ifindex 2
    if (ip->protocol == IPPROTO_TCP) {
        return bpf_redirect(2, 0);
    }
    // Redirect UDP traffic to ifindex 3
    else if (ip->protocol == IPPROTO_UDP) {
        return bpf_redirect(3, 0);
    }

    // Pass all other traffic
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
