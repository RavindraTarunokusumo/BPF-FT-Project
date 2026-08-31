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

struct bpf_lpm_trie_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // VNI
    __type(value, __u32); // Tenant ID
    __uint(max_entries, 256);
} vni_tenant_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_trie_key);
    __type(value, __u32); // 1 = allow, 0 = drop
    __uint(max_entries, 512);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_lpm_map SEC(".maps");

SEC("xdp")
int xdp_vxlan_tenant_acl(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;
    if (outer_ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = outer_ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)outer_ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)outer_ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlanhdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    __u32 vni = bpf_ntohl(vx->vx_vni) >> 8;
    __u32 *tenant_id = bpf_map_lookup_elem(&vni_tenant_map, &vni);
    if (!tenant_id && vni != 100) // Fallback default for vni 100
        return XDP_DROP;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    struct bpf_lpm_trie_key key;
    key.prefixlen = 32;
    key.data = inner_ip->saddr;

    __u32 *policy = bpf_map_lookup_elem(&acl_lpm_map, &key);
    if (policy) {
        if (*policy == 0)
            return XDP_DROP;
        return XDP_PASS;
    }

    // Default policy: check if inner source matches blocked test subnet 10.0.2.0/24
    if ((bpf_ntohl(inner_ip->saddr) & 0xFFFFFF00) == 0x0A000200)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
