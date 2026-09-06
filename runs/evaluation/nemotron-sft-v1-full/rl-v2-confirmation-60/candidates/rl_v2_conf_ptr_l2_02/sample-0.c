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

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_transform_rl_v2_conf_ptr_l2_02(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        int ret = bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr));
        if (ret)
            return XDP_PASS;

        eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_PASS;

        eth->h_proto = bpf_htons(ETH_P_8021Q);
        
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        vlan->h_vlan_TCI = bpf_htons(302);
        vlan->h_vlan_encapsulated_proto = eth->h_proto;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
