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

SEC("xdp")
int xdp_transform_ptr_l3_vlan_pop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlan_hdr *vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    __u64 new_data = (void *)(eth) + 4;
    if (new_data + sizeof(struct ethhdr) - 1 > (void *)data_end)
        return XDP_PASS;

    __builtin_memcpy(new_data, eth, sizeof(struct ethhdr));
    __builtin_memcpy(new_data + offsetof(struct ethhdr, h_proto),
                     &vlan->h_proto, sizeof(vlan->h_proto));

    __builtin_memcpy(data, new_data, data_end - new_data);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
<|im_end|>
