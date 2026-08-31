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
int xdp_transform_syn_ptr_l3_001_vxlan_encap_push(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u64 headroom_needed = 50 + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vxlanhdr);
    if ((void *)ip + ip->ihl*4 > data_end)
        return XDP_PASS;

    int err = bpf_xdp_adjust_head(ctx, -headroom_needed);
    if (err)
        return XDP_PASS;

    void *new_data = data;
    struct ethhdr *new_eth = new_data;
    memset(new_eth, 0, sizeof(*new_eth));
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *new_ip = (void *)(new_eth + 1);
    memset(new_ip, 0, sizeof(*new_ip));
    new_ip->protocol = IPPROTO_UDP;
    new_ip->ttl = 64;
    new_ip->check = 0;
    new_ip->saddr = inet_addr("192.168.1.1");
    new_ip->daddr = inet_addr("192.168.1.254");

    __u64 ip_hdr_len = new_ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)new_ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)new_ip + ip_hdr_len;
    memset(udp, 0, sizeof(*udp));
    udp->dest = bpf_htons(4789);

    __u64 udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    struct vxlanhdr *vxlan = (void *)udp + udp_hdr_len;
    memset(vxlan, 0, sizeof(*vxlan));
    vxlan->vni = bpf_htons(100);
    vxlan->flags = VXLANhdr_flags_GRENAT;

    __u64 vxlan_hdr_len = sizeof(struct vxlanhdr);
    if ((void *)vxlan + vxlan_hdr_len > data_end)
        return XDP_PASS;

    // Compute IP checksum
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < sizeof(struct iphdr); i += 2) {
        __u16 w = ((__u8 *)new_ip)[i] + ((__u8 *)new_ip)[i+1] * 256;
        csum += w;
        while (csum >= 0x10000)
            csum -= 0xFFFF;
    }
    new_ip->check = (__u16)csum;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
