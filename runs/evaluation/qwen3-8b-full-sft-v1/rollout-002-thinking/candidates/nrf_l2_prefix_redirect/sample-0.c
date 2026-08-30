#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} prefix_config_2 SEC(".maps");

SEC("xdp")
int xdp_route_nrf_l2_prefix_redirect(struct xdp_md *ctx) {
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

    __u32 daddr = ip->daddr;

    __u32 prefix1 = 0x0A000000;
    if ((daddr & 0xFF000000) == prefix1) {
        __u32 *ifindex = bpf_map_lookup_elem(&prefix_config_2, &0);
        if (ifindex && *ifindex > 0)
            return bpf_redirect(*ifindex, 0);
    }

    __u32 prefix2 = 0xAC100000;
    if ((daddr & 0xFFF00000) == prefix2) {
        __u32 *ifindex = bpf_map_lookup_elem(&prefix_config_2, &1);
        if (ifindex && *ifindex > 0)
            return bpf_redirect(*ifindex, 0);
    }

    return XDP_PASS;
}

SEC("license")
char _license[] SEC("license") = "GPL";
