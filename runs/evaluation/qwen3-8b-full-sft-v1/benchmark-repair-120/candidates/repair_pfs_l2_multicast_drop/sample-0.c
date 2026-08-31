#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_dest[0] & 0x01) {
        // Multicast MAC address
        if (eth->h_dest[0] == 0x01 && eth->h_dest[1] == 0x00 && eth->h_dest[2] == 0x5E)
            return XDP_DROP;
        // Exclude broadcast
        if (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff && eth->h_dest[2] == 0xff)
            return XDP_PASS;
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 first_byte = *(__u8 *)&ip->daddr;
    if ((first_byte & 0xF0) == 0xE0)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
