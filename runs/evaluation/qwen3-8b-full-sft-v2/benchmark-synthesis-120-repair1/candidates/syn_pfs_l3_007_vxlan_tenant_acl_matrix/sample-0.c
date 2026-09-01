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

struct vxlan_hdr {
    __be32 flags;
    __be32 vni;
};

SEC("xdp")
int xdp_vxlan_tenant_acl_matrix(struct xdp_md *ctx) {
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlan_hdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    __u32 vni = bpf_ntohl(vx->vni) >> 8;
    __u32 *tenant_id = bpf_map_lookup_elem(&vni_tenant_map, &vni);
    if (!tenant_id || *tenant_id != 100)
        return XDP_DROP;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_hlen_inner = inner_ip->ihl * 4;
    if (ip_hlen_inner < sizeof(*inner_ip) || ip_hlen_inner > 60)
        return XDP_PASS;

    struct bpf_lpm_trie_key key = {};
    key.family = BPF_LPM_TRIE_IP4;
    __builtin_memcpy(key.key, &inner_ip->saddr, sizeof(inner_ip->saddr));
    key.key_len = sizeof(inner_ip->saddr);

    __u32 *policy = bpf_map_lookup_elem(&acl_lpm_map, &key);
    if (!policy || *policy == 0) {
        if (inner_ip->saddr == bpf_htons(10 * 256 * 256 + 0 * 256 + 2))
            return XDP_DROP;
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";