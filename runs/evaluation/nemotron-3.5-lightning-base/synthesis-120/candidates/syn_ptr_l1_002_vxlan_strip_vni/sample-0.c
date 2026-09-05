/* XDP program: VXLAN VNI strip/rewrite
 *
 * Inspects VXLAN packets (UDP destination port 4789) and rewrites
 * the 24-bit Virtual Network Identifier (VNI) field to fixed value
 * 0x00AABB (0x00AABB00 in network byte order).
 *
 * Validates Ethernet, IPv4, UDP, and struct vxlanhdr bounds.
 * Always returns XDP_PASS.
 *
 * This program requires XDP with AF_INET or AF_INET6 and
 * a valid struct vxlanhdr layout (typically 8 bytes).
 *
 * License: GPL
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/vxlan.h>

/* Helper: load 32-bit value from memory with bounds check.
 * Returns 0 and sets *ok = 0 on failure. */
static __always_inline int load_u32(void *data, void *data_end,
                                    void *ptr, __u32 *val)
{
    if (ptr + sizeof(__u32) > data_end)
        return 0;
    *val = bpf_ldx_4(ptr);
    return 1;
}

SEC("xdp")
int xdp_vxlan_vni_strip(void *ctx)
{
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct vxlanhdr *vx;
    __u32 vni_net;
    void *data, *data_end;

    data = (void *)(long)bpf_xdp_load_frame(ctx, &data_end);
    if (!data)
        return XDP_ABORTED;

    /* 1. Validate Ethernet frame minimum size */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Validate IPv4 protocol */
    /* Accept only IPv4 (ETH_P_IP = 0x0800) */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    /* 3. Validate IPv4 header */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);
    /* Verify IP header length is at least minimum (20 bytes) */
    if (ip->ihl < 5)
        return XDP_PASS;

    /* 4. Validate UDP protocol (protocol field = IPPROTO_UDP = 17) */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 5. Validate UDP header */
    /* UDP header starts after IP header */
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = data + sizeof(*eth) + ip->ihl * 4;

    /* 6. Verify UDP destination port is 4789 (VXLAN) */
    if (bpf_ntohs(udp->dest) != 4789)
        return XDP_PASS;

    /* 7. Validate VXLAN header bounds */
    /* VXLAN header follows UDP payload */
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) +
        sizeof(*vx) > data_end)
        return XDP_PASS;

    vx = (void *)udp + sizeof(*udp);

    /* 8. Read and rewrite VNI field (24 bits valid, MSB is reserved) */
    /* Load vx->vx_vni (32-bit) from network byte order */
    if (!load_u32(data, data_end, &vx->vx_vni, &vni_net))
        return XDP_PASS;

    /* Rewrite to 0x00AABB00 in network byte order.
     * bpf_htonl ensures correct byte order for the host.
     * Value 0x00AABB00 becomes wire format: 0x00 0xAA 0xBB 0x00 */
    vx->vx_vni = bpf_htonl(0x00AABB00);

    /* Packet modified successfully, continue processing */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
