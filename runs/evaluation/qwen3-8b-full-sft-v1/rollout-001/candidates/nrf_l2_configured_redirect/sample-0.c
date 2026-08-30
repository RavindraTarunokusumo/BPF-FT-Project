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
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} forwarding_config_2 SEC(".maps");

SEC("xdp")
int xdp_route_nrf_l2_configured_redirect(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if ((void *)(uintptr_t)data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u32 *ifindex = bpf_map_lookup_elem(&forwarding_config_2, &0);
    if (!ifindex || *ifindex == 0)
        return XDP_ABORTED;

    return bpf_redirect(*ifindex, 0);
}

char _license[] SEC("license") = "GPL";
<|im_end|>
