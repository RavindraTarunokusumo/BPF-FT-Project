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
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    // Subnet check for 198.51.100.0/24 (0xC6336400)
    __u32 subnet = bpf_htonl(0xC6336400);
    __u32 mask = bpf_htonl(0xFFFFFF00);
    if (( (__u32 *)&ip->saddr & mask) == subnet) {
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ip_len;
            if ((void *)(udp + 1) <= data_end && udp->dest == bpf_htons(53))
                return XDP_PASS;
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
