#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

SEC("xdp")
int xdp_evpn_gw_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlanhdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    // Check Anycast GW MAC 00:00:5e:00:01:01
    if (inner_eth->h_dest[0] == 0x00 && inner_eth->h_dest[1] == 0x00 &&
        inner_eth->h_dest[2] == 0x5E && inner_eth->h_dest[3] == 0x00 &&
        inner_eth->h_dest[4] == 0x01 && inner_eth->h_dest[5] == 0x01) {

        if (inner_eth->h_proto == bpf_htons(ETH_P_IP)) {
            struct iphdr *inner_ip = (void *)(inner_eth + 1);
            if ((void *)(inner_ip + 1) > data_end)
                return XDP_PASS;

            __u32 dst = bpf_ntohl(inner_ip->daddr);
            if ((dst & 0xFFFFFF00) == 0x0A000100) // 10.0.1.0/24
                return bpf_redirect(70, 0);
            if ((dst & 0xFFFFFF00) == 0x0A000200) // 10.0.2.0/24
                return bpf_redirect(71, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
