#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct vlanhdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_pcp_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlanhdr *vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    __u8 pcp = bpf_ntohs(vlan->h_vlan_TCI) >> 13;
    if (pcp >= 5)
        return bpf_redirect(8, 0);
    else
        return bpf_redirect(9, 0);
}

char _license[] SEC("license") = "GPL";
