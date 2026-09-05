#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/vxlan.h>

/* XDP program entry point */
SEC("xdp")
int xdp_vxlan_vni_dispatcher(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct vxlanhdr *vxlan;
    __u16 vni;

    /* 1. Validate Ethernet frame bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Validate IPv4 protocol */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Validate IPv4 header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);

    /* 4. Verify IPv4 protocol is UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 5. Validate UDP header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = (struct udphdr *)(ip + 1);

    /* 6. Verify UDP destination port is VXLAN (4789) */
    if (udp->dest != htons(4789))
        return XDP_PASS;

    /* 7. Validate VXLAN header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*vxlan) > data_end)
        return XDP_PASS;

    vxlan = (struct vxlanhdr *)(udp + 1);

    /* 8. Extract VNI (24 bits, mask to get VNI, shift right 8 to get 24-bit value) */
    vni = ntohl(vxlan->vni) & 0x00FFFFFF;

    /* 9. Dispatch based on VNI */
    if (vni == 100) {
        /* Redirect to tenant 1 interface ifindex 40 */
        return bpf_redirect(40, 0);
    } else if (vni == 200) {
        /* Redirect to tenant 2 interface ifindex 41 */
        return bpf_redirect(41, 0);
    }

    /* 10. Pass all other VNIs and non-VXLAN traffic */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
SEC("xdp")
