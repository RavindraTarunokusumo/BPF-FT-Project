#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check Ethernet type is IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header bounds
    struct iphdr *ip = (struct iphdr *)((void *)data + ETH_HLEN);
    if ((void *)ip + 20 > data_end)
        return XDP_PASS;

    // Extract destination IP address
    __be32 daddr = ip->daddr;
    __be32 masked_daddr;

    // Check 10.0.0.0/8 prefix
    masked_daddr = bpf_ntohl(daddr) & 0xFF000000;
    if (masked_daddr == 0x0A000000) {
        __u32 key_0 = 0;
        __u32 ifindex = bpf_map_lookup_elem(&prefix_config, &key_0);
        if (ifindex) {
            return bpf_redirect(ifindex, 0);
        }
    }

    // Check 172.16.0.0/12 prefix
    masked_daddr = bpf_ntohl(daddr) & 0xFFF00000;
    if (masked_daddr == 0xAC100000) {
        __u32 key_1 = 1;
        __u32 ifindex = bpf_map_lookup_elem(&prefix_config, &key_1);
        if (ifindex) {
            return bpf_redirect(ifindex, 0);
        }
    }

    return XDP_PASS;
}

SEC("maps")
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} prefix_config SEC(".maps");
