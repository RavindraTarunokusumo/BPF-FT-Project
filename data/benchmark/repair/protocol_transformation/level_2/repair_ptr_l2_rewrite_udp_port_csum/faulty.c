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
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    // Compilation error: struct udphdr incomplete without <linux/udp.h>
    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(53)) {
        udp->dest = bpf_htons(5353);
        if (udp->check != 0) {
            __u32 csum = bpf_ntohs(udp->check);
            csum += 53 + (~5353 & 0xFFFF);
            while (csum >> 16)
                csum = (csum & 0xFFFF) + (csum >> 16);
            if (csum == 0)
                csum = 0xFFFF;
            udp->check = bpf_htons((__u16)csum);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
