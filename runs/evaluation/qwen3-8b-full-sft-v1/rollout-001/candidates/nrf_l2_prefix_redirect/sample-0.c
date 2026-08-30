#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
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

    __u8 *d = (void *)&ip->daddr;
    if (d[0] == 0x0A && d[1] == 0x00 && d[2] == 0x00 && d[3] == 0x00) {
        __u32 key = 0;
        __u32 *ifindex = bpf_map_lookup_elem(&prefix_config_2, &key);
        if (ifindex && *ifindex > 0)
            return bpf_redirect(*ifindex, 0);
    }

    d = (void *)&ip->saddr;
    if (d[0] == 0x0A && d[1] == 0x00 && d[2] == 0x00 && d[3] == 0x00) {
        __u32 key = 0;
        __u32 *ifindex = bpf_map_lookup_elem(&prefix_config_2, &key);
        if (ifindex && *ifindex > 0)
            return bpf_redirect(*ifindex, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
<|im_end|>
