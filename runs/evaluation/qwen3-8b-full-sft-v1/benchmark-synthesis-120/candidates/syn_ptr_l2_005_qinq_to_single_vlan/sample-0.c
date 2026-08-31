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
int xdp_transform_syn_ptr_l2_005(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlanhdr *vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    if (vlan->h_vlan_TCI != 0x1234)
        return XDP_PASS;

    __u8 *new_data = (void *)(eth + 1) - 4;
    if (new_data < data)
        return XDP_PASS;

    struct ethhdr *new_eth = new_data;
    __builtin_memcpy(new_eth, eth, sizeof(*eth));
    new_eth->h_proto = bpf_htons(ETH_P_8021Q);
    __builtin_memcpy(new_eth + 1, vlan + 1, sizeof(struct ethhdr) - sizeof(eth->h_proto) + sizeof(vlan->h_vlan_TCI));
    
    return bpf_xdp_adjust_head(ctx, 4);
}

char _license[] SEC("license") = "GPL";
