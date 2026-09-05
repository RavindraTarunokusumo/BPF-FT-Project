#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_vlan.h>

/* XDP program entry point */
SEC("xdp")
int xdp_vlan_encap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Check if frame is untagged IPv4 (eth->h_proto == ETH_P_IP) */
    if (eth->h_proto != ETH_P_IP)
        return XDP_PASS;

    /* 3. Invoke bpf_xdp_adjust_head to expand head by sizeof(struct vlan_hdr) */
    int ret = bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr));
    if (ret)
        return XDP_PASS;

    /* 4. Re-validate packet pointers after head adjustment */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify that the Ethernet header is still within bounds */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 5. Rewrite Ethernet header with ETH_P_8021Q (0x8100) */
    eth->h_proto = htons(ETH_P_8021Q);

    /* 6. Insert struct vlan_hdr with vlan_id == 301 and encapsulated ETH_P_IP */
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    /* Ensure vlan header fits within data_end */
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    vlan->h_vlan_TCI = 0;                          /* TCI bits */
    vlan->h_vlan_encapsulated_proto = htons(ETH_P_IP);

    /* Set VLAN ID = 301 (0x012D) in the TCI field */
    vlan->h_vlan_TCI |= cpu_to_be16(301 << VLAN_VID_SHIFT);

    /* 7. Return XDP_PASS unconditionally */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
