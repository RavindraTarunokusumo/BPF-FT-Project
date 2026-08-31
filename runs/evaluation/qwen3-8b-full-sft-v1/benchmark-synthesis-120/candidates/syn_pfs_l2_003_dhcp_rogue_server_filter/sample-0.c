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


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __be32);
} auth_dhcp_server_3 SEC(".maps");

SEC("xdp")
int xdp_filter_syn_pfs_l2_003_dhcp_rogue_server(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    unsigned int udp_hdr_start = ip_hdr_len;
    if (udp_hdr_start >= data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->source != bpf_htons(67) || udp->dest != bpf_htons(68))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if (udp_hdr_start + udp_hdr_len > data_end)
        return XDP_PASS;

    unsigned int dhcp_hdr_start = udp_hdr_start + udp_hdr_len;
    if (dhcp_hdr_start >= data_end)
        return XDP_PASS;

    struct dhcp_hdr *dhcp = (void *)udp + 1;
    if ((void *)(dhcp + 1) > data_end)
        return XDP_PASS;

    if (dhcp->op != bpf_htons(2))
        return XDP_PASS;

    __u8 *p = (void *)dhcp + sizeof(struct dhcp_hdr);
    if (p + 4 > (void *)dhcp + sizeof(struct dhcp_hdr))
        return XDP_PASS;

    if (p[0] != 0x63 || p[1] != 0x82 || p[2] != 0x53 || p[3] != 0x63)
        return XDP_PASS;

    __u32 *server_ip = bpf_map_lookup_elem(&auth_dhcp_server_3, NULL);
    if (!server_ip) {
        __u32 fallback = bpf_htons(0xC0A80101);
        if (ip->saddr != fallback)
            return XDP_DROP;
        return XDP_PASS;
    }

    if (ip->saddr != *server_ip)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
