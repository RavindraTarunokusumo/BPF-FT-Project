#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlh = (void *)(eth + 1);
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;

        __u16 vid = bpf_ntohs(vlh->h_vlan_TCI) & 0x0FFF;
        if (vid == 10)
            return bpf_redirect(2, 0);
        else if (vid == 20)
            return bpf_redirect(3, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
