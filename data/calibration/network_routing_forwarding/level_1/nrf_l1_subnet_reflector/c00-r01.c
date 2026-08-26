#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_reflect_subnet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IPv4 header bounds
    void *ip_data = data + sizeof(struct ethhdr);
    if (ip_data + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = ip_data;
    if (ip->version != 4)
        return XDP_PASS;

    // Check destination subnet (192.0.2.0/24)
    __u32 daddr = bpf_ntohl(ip->daddr);
    if ((daddr & 0xFFFFFF00) == 0xC0000200) {
        // Swap Ethernet source and destination MAC addresses
        void *src_mac = eth->h_source;
        void *dst_mac = eth->h_dest;
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = ((char *)src_mac)[i];
        }
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_source[i] = ((char *)dst_mac)[i];
        }
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
