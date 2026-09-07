/* XDP EVPN Distributed Anycast Gateway
 * Inspects VXLAN encapsulated traffic (UDP port 4789)
 * Redirects inner packets based on inner IPv4 destination
 * to specific interfaces for distributed gateway functionality.
 *
 * Compilation: clang -target bpf -O2 -c xdp_evpn_gw.c -o xdp_evpn_gw.o
 * Load:      ip xdp add xdp evpn_gw dev eth0
 * Unload:    ip xdp del xdp evpn_gw dev eth0
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* VXLAN header: 8 bytes after UDP header */
struct vxlan_hdr {
    __be32	vxlan_flags;
    __be32	vxlan_vni;
};

/* XDP program entry point */
SEC("xdp")
int xdp_evpn_gw(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *inner_ip;
    struct udphdr *udp;
    struct vxlan_hdr *vxlan;
    __u16 inner_eth_type;
    __u32 inner_ip_dst;

    /* 1. Validate outer Ethernet header */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    eth = data;

    /* 2. Validate IPv4 outer header */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    if (data + sizeof(*eth) + sizeof(*eth->h_dest) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    /* 3. Validate UDP header and VXLAN encapsulation */
    if (ctx->data + sizeof(*eth) + sizeof(struct iphdr) + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = data + sizeof(*eth) + sizeof(struct iphdr);
    if (udp->dest != bpf_htons(4789)) /* VXLAN UDP port */
        return XDP_PASS;

    /* 4. Validate VXLAN header */
    if (ctx->data + sizeof(*eth) + sizeof(struct iphdr) + sizeof(*udp) + sizeof(*vxlan) > data_end)
        return XDP_PASS;

    vxlan = (struct vxlan_hdr *)(udp + 1);
    /* Check VXLAN flags: bit 31 must be set (0x80000000) */
    if (!(vxlan->vxlan_flags & bpf_htonl(0x80000000)))
        return XDP_PASS;

    /* 5. Validate inner Ethernet header */
    /* Inner Ethernet starts right after VXLAN header */
    if (ctx->data + sizeof(*eth) + sizeof(struct iphdr) + sizeof(*udp) + sizeof(*vxlan) + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Skip to inner Ethernet */
    data += sizeof(*eth) + sizeof(struct iphdr) + sizeof(*udp) + sizeof(*vxlan);
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;
    inner_eth_type = eth->h_proto;

    /* 6. Verify inner destination MAC matches anycast gateway MAC:
     *    00:00:5e:00:01:01 */
    /* Compare 6 bytes of h_dest with the anycast MAC */
    if (eth->h_dest[0] != 0x00 ||
        eth->h_dest[1] != 0x00 ||
        eth->h_dest[2] != 0x5e ||
        eth->h_dest[3] != 0x00 ||
        eth->h_dest[4] != 0x01 ||
        eth->h_dest[5] != 0x01)
        return XDP_PASS;

    /* 7. Validate inner IPv4 header */
    if (inner_eth_type != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if (data + sizeof(*eth) + sizeof(*inner_ip) > data_end)
        return XDP_PASS;

    inner_ip = data + sizeof(*eth);

    /* 8. Check inner IPv4 destination */
    inner_ip_dst = inner_ip->daddr;

    if (inner_ip_dst >= bpf_htonl(0x0a000100) && /* 10.0.1.0 */
        inner_ip_dst <= bpf_htonl(0x0a0001ff)) { /* 10.0.1.255 */
        /* Redirect to ifindex 70 */
        return bpf_redirect(70, 0);
    }

    if (inner_ip_dst >= bpf_htonl(0x0a000200) && /* 10.0.2.0 */
        inner_ip_dst <= bpf_htonl(0x0a0002ff)) { /* 10.0.2.255 */
        /* Redirect to ifindex 71 */
        return bpf_redirect(71, 0);
    }

    /* 9. Pass other traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
