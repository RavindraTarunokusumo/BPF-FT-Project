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


struct vni_key {
    __u32 vni;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct vni_key);
    __type(value, __u32);
} vni_tenant_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 512);
    __type(key, struct bpf_lpm_trie_key);
    __type(value, __u32);
} acl_lpm_map SEC(".maps");

SEC("xdp")
int xdp_filter_syn_pfs_l3_007_vxlan_tenant_acl_matrix(struct xdp_md *ctx) {
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

    __u32 vni = udp->source & 0x00FFFFFF;
    
    struct vni_key key = {};
    key.vni = vni;
    
    __u32 *tenant_id = bpf_map_lookup_elem(&vni_tenant_map, &key);
    if (!tenant_id) {
        if (vni != 100)
            return XDP_DROP;
        return XDP_PASS;
    }

    struct ethhdr *inner_eth = (void *)(udp + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    struct bpf_lpm_trie_key key_lpm = {};
    __u8 *p = (void *)&inner_ip->saddr;
    __u8 *e = p + 4;
    while (p < e)
        key_lpm.prefix[p - (void *)&inner_ip->saddr] = *p++;

    __u32 *policy = bpf_map_lookup_elem(&acl_lpm_map, &key_lpm);
    if (policy && *policy == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
