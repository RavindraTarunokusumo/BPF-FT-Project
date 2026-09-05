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
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Block source IP addresses in 172.16.0.0/16.
       Mask with 0xFFFF0000 to inspect the first two octets (172.16.x.x).
       0xAC100000 = 172.16.0.0 in network byte order. */
    __u32 mask = bpf_htonl(0xFFFF0000);
    __u32 subnet = bpf_htonl(0xAC100000);

    if ((ip->saddr & mask) == (subnet & mask))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
