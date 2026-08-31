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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} vni_tenant_map_7 SEC(".maps");

struct lpm_key {
    __u32 prefix;
    __u8  bits;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 512);
    __type(key, struct lpm_key);
    __type(value, __u32);
} acl_lpm_map_7 SEC(".maps");

SEC("xdp")
int xdp_tenant_vxlan_acl_pfs_l3_007(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_VXLAN))
        return XDP_PASS;

    struct vxlan_hdr *vxlan = (void *)(eth + 1);
    if ((void *)(vxlan + 1) > data_end)
        return XDP_PASS;

    __u32 vni = vxlan->vni;
    __u32 *tenant_id = bpf_map_lookup_elem(&vni_tenant_map_7, &vni);
    if (!tenant_id || *tenant_id != 100)
        return XDP_DROP;

    if ((void *)(vxlan + 1) > data_end)
        return XDP_PASS;

    unsigned int ip_hdr_len = vxlan->hdr_len;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)vxlan + ip_hdr_len > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)vxlan + ip_hdr_len;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int tcp_hdr_len = ip->ihl * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)ip + tcp_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + tcp_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest != bpf_htons(80) && tcp->dest != bpf_htons(443))
        return XDP_PASS;

    __u8 *d = (void *)(tcp + 1);
    if (d < data_end) {
        if (ip->daddr == bpf_htons(10 * 256 * 256 + 0 * 256 + 2))
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
