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

struct dhcp_hdr {
    __be32 op;
    __be32 hw_type;
    __be16 hw_len;
    __be16 proto;
    __be16 hops;
    __be32 xid;
    __be16 secs;
    __be16 flags;
    __be32 ciaddr;
    __be32 yiaddr;
    __be32 siaddr;
    __be32 giaddr;
    __be88 chaddr;
    __be16 sname[16];
    __be16 file[16];
    __be32 magic;
};

SEC("xdp")
int xdp_filter_syn_pfs_l2_003_dhcp_rogue_server_filter(struct xdp_md *ctx) {
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

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->source != bpf_htons(67) || udp->dest != bpf_htons(68))
        return XDP_PASS;

    struct dhcp_hdr *dhcp = (void *)(udp + 1);
    if ((void *)(dhcp + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __be32 *auth_ip = bpf_map_lookup_elem(&auth_dhcp_server, &key);
    if (!auth_ip)
        auth_ip = (void *)&(0xC0A80101); // Fallback to 192.168.1.1

    if (ip->saddr != *auth_ip)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
