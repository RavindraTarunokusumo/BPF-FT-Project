#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_qinq_double_vlan_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet header presence and bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Check for QinQ outer tag: 0x88A8 (QinQ) or 0x8100 (standard 802.1Q) */
    __be16 ethertype = eth->h_proto;
    if (ethertype != bpf_htonl(0x88A8) && ethertype != bpf_htonl(0x8100))
        return XDP_PASS;

    /* 3. Validate outer VLAN header bounds */
    struct vlan_hdr *outer_vlan = (struct vlan_hdr *)(eth + 1);
    if ((void *)(outer_vlan + 1) > data_end)
        return XDP_PASS;

    /* 4. Verify outer EtherType is 0x8100 (802.1Q) */
    if (outer_vlan->h_vlan_encapsulated_proto != bpf_htonl(0x8100))
        return XDP_PASS;

    /* 5. Validate inner VLAN header bounds */
    void *inner_vlan_start = (void *)(outer_vlan + 1);
    if (inner_vlan_start + sizeof(struct vlan_hdr) > data_end)
        return XDP_PASS;

    struct vlan_hdr *inner_vlan = (struct vlan_hdr *)inner_vlan_start;

    /* 6. Verify inner EtherType is 0x8100 */
    if (inner_vlan->h_vlan_encapsulated_proto != bpf_htonl(0x8100))
        return XDP_PASS;

    /* 7. Extract 12-bit VLAN IDs */
    __be16 outer_tci = outer_vlan->h_vlan_TCI;
    __be16 inner_tci = inner_vlan->h_vlan_TCI;
    __u16 outer_vid = ntohs(outer_tci) & 0x0FFF;
    __u16 inner_vid = ntohs(inner_tci) & 0x0FFF;

    /* 8. Drop if outer_vid == 100 && inner_vid == 200 */
    if (outer_vid == 100 && inner_vid == 200)
        return XDP_DROP;

    /* All other cases pass */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
